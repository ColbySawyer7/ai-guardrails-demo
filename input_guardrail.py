import os
from typing import List, Tuple, Any, Dict
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough, RunnableSequence
import sqlite3
from typing import Optional
from dataclasses import dataclass
from enum import Enum

# Load environment variables
load_dotenv()

class AccessLevel(Enum):
    UNAUTHORIZED = 0
    BASIC = 1
    ADMIN = 2

@dataclass
class User:
    id: int
    username: str  # Using email as username
    access_level: AccessLevel
    first_name: str
    last_name: str

def get_random_user() -> Optional[User]:
    """Get a random user from the database to simulate a logged-in user."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, email, first_name, last_name 
            FROM users 
            ORDER BY RANDOM() 
            LIMIT 1
        """)
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return User(
                id=result[0],
                username=result[1],
                access_level=AccessLevel.BASIC,  # All users get basic access
                first_name=result[2],
                last_name=result[3]
            )
        return None
    except sqlite3.Error as e:
        print(f"Error getting random user: {e}")
        return None

def create_guardrail_chain(current_user: User) -> RunnableSequence:
    """Create a chain that verifies user identity and query safety."""
    llm = ChatOpenAI(
        base_url="https://openrouter.ai/api/v1",
        model="gpt-3.5-turbo",
        temperature=0,
        streaming=True
    )

    guardrail_prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=f"""You are a security guardrail system that verifies user identity and query safety.
        Current user: {current_user.first_name} {current_user.last_name} (ID: {current_user.id}, Email: {current_user.username})
        
        Your job is to:
        1. Convert natural language queries into SQL queries that only access the current user's data
        2. Check if the query might expose sensitive information
        3. Return a response in EXACTLY this format:
        authorized: true/false
        reason: <explanation>
        sensitive_fields: [field1, field2, ...]
        sql_query: <SQL query if authorized>

        Rules:
        - Users can ONLY access their own data (must include WHERE id = {current_user.id})
        - Sensitive fields include: ssn, phone_number, address, date_of_birth
        - Users can see their own: first_name, last_name, email, address, phone_number, date_of_birth
        - Natural language queries about the user's own data should be converted to SQL
        - Always err on the side of caution when protecting user data
        
        Examples of natural language to SQL conversion:
        - "What's my address?" -> "SELECT address FROM users WHERE id = {current_user.id}"
        - "Where do I live?" -> "SELECT address FROM users WHERE id = {current_user.id}"
        - "What's my phone number?" -> "SELECT phone_number FROM users WHERE id = {current_user.id}"
        - "When was I born?" -> "SELECT date_of_birth FROM users WHERE id = {current_user.id}"
        - "What's my email?" -> "SELECT email FROM users WHERE id = {current_user.id}"
        - "What's my name?" -> "SELECT first_name, last_name FROM users WHERE id = {current_user.id}"
        
        Example denied queries:
        - "What's Steven's address?" (trying to access another user's data)
        - "Show me all users" (no user restriction)
        - "What's my SSN?" (sensitive data)

        Example response for "What's my address?":
        authorized: true
        reason: User is requesting their own address
        sensitive_fields: []
        sql_query: SELECT address FROM users WHERE id = {current_user.id}

        Example response for "What's Steven's address?":
        authorized: false
        reason: Cannot access another user's data
        sensitive_fields: []
        sql_query: null"""),
        ("human", "Query: {query}")
    ])

    def parse_guardrail_response(response: str) -> Dict[str, Any]:
        """Parse the guardrail response into a structured format."""
        try:
            # Debug print
            print("\nGuardrail Response:")
            print(response)
            print("---")

            # Initialize default values
            result = {
                "authorized": False,
                "reason": "Invalid response format",
                "sensitive_fields": [],
                "sql_query": None
            }

            # Parse each line
            for line in response.split('\n'):
                line = line.strip().lower()
                if not line:
                    continue
                
                if line.startswith('authorized:'):
                    result["authorized"] = 'true' in line
                elif line.startswith('reason:'):
                    result["reason"] = line.replace('reason:', '').strip()
                elif line.startswith('sensitive_fields:'):
                    fields_str = line.replace('sensitive_fields:', '').strip()
                    if fields_str and fields_str != '[]':
                        result["sensitive_fields"] = [f.strip() for f in fields_str.strip('[]').split(',')]
                elif line.startswith('sql_query:'):
                    query = line.replace('sql_query:', '').strip()
                    if query and query.lower() != 'null':
                        result["sql_query"] = query

            return result
        except Exception as e:
            print(f"Error parsing guardrail response: {e}")
            return {
                "authorized": False,
                "reason": f"Error parsing response: {str(e)}",
                "sensitive_fields": [],
                "sql_query": None
            }

    return (
        {"query": RunnablePassthrough()}
        | guardrail_prompt
        | llm
        | StrOutputParser()
        | parse_guardrail_response
    )

# Database connection
def get_db_connection() -> sqlite3.Connection:
    """Get a connection to the SQLite database."""
    return sqlite3.connect("users.db")

@tool
def query_database(query: str) -> str:
    """Query the users database. The database has a 'users' table with the following columns:
    - id (INTEGER, PRIMARY KEY)
    - first_name (TEXT)
    - last_name (TEXT)
    - email (TEXT, UNIQUE)
    - phone_number (TEXT)
    - date_of_birth (DATE)
    - address (TEXT)
    - ssn (TEXT, UNIQUE)
    - created_at (TIMESTAMP)
    
    Use this tool to answer questions about user data. For name searches, use LIKE with % for partial matches.
    Example queries:
    - "SELECT COUNT(*) FROM users"
    - "SELECT first_name, last_name, email FROM users WHERE date_of_birth > '1990-01-01'"
    - "SELECT first_name, last_name, address FROM users WHERE first_name LIKE '%John%' OR last_name LIKE '%Smith%'"
    - "SELECT first_name, last_name, address FROM users LIMIT 5"
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Execute the query
        cursor.execute(query)
        
        # Get column names
        columns = [description[0] for description in cursor.description]
        
        # Fetch results
        results = cursor.fetchall()
        
        # Format results
        if not results:
            return "No results found."
            
        # For single column queries, return just the value
        if len(columns) == 1:
            value = results[0][0]
            if value is None:
                return "No data available"
            return str(value)
        
        # For multiple columns, create a formatted table
        output = []
        for row in results:
            # Format each value, handling None values
            formatted_row = []
            for value in row:
                if value is None:
                    formatted_row.append("N/A")
                else:
                    formatted_row.append(str(value))
            output.append(" | ".join(formatted_row))
            
        conn.close()
        return "\n".join(output)
        
    except sqlite3.Error as e:
        return f"Database error: {str(e)}"
    except Exception as e:
        return f"Error executing query: {str(e)}"

def create_protected_agent(current_user: User) -> RunnableSequence:
    """Create a chain that combines the guardrail with the agent for protected database access."""
    # Initialize the language model
    llm = ChatOpenAI(
        base_url="https://openrouter.ai/api/v1",
        model="gpt-3.5-turbo",
        temperature=0,
        streaming=True
    )

    # Create the guardrail chain
    guardrail_chain = create_guardrail_chain(current_user)

    # Define the tools
    tools = [query_database]

    # Create the prompt template with database context
    system_message = """You are a helpful AI assistant with access to a SQLite database containing user information.
    The database has a 'users' table with the following columns:
    - id (INTEGER, PRIMARY KEY)
    - first_name (TEXT)
    - last_name (TEXT)
    - email (TEXT, UNIQUE)
    - phone_number (TEXT)
    - date_of_birth (DATE)
    - address (TEXT)
    - ssn (TEXT, UNIQUE)
    - created_at (TIMESTAMP)

    You can use the query_database tool to answer questions about the user data.
    For name searches, use LIKE with % for partial matches (e.g., "WHERE first_name LIKE '%John%'").
    Always use parameterized queries for safety and only return necessary information.
    For privacy reasons, never return SSN numbers in your responses.
    If a name search returns no results, try using partial matches with LIKE.
    Use the other tools (get_weather, search_web) for general questions."""

    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=system_message),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    # Create the agent
    agent = create_openai_tools_agent(llm, tools, prompt)
    
    # Create the agent executor
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True
    )

    def process_guardrail_result(guardrail_result: Dict[str, Any], original_input: str) -> str:
        """Process the guardrail result and return appropriate response."""
        if not guardrail_result["authorized"]:
            return f"Access Denied: {guardrail_result['reason']}" + \
                   (f"\nSensitive fields detected: {', '.join(guardrail_result['sensitive_fields'])}" 
                    if guardrail_result["sensitive_fields"] else "")
        
        # If authorized and SQL query was generated, use it directly
        if guardrail_result["sql_query"]:
            sql_query = guardrail_result["sql_query"].format(current_user=current_user)
            return query_database.invoke(sql_query)
        
        # If authorized but no SQL query, proceed with the agent
        agent_response = agent_executor.invoke({
            "input": original_input,
            "chat_history": []
        })
        return agent_response["output"]

    # Create the protected chain using proper piping
    return (
        RunnablePassthrough.assign(
            guardrail_result=lambda x: guardrail_chain.invoke(x["input"])
        )
        | (lambda x: process_guardrail_result(x["guardrail_result"], x["input"]))
    )

def main():
    # Get a random user for this session
    current_user = get_random_user()
    if not current_user:
        print("Error: Could not get a user from the database. Please ensure the database is populated.")
        return

    # Create the protected agent chain
    protected_agent = create_protected_agent(current_user)
    
    # Initialize chat history as a list of messages
    chat_history: List[Tuple[HumanMessage, AIMessage]] = []
    
    print("Welcome to the AI Assistant! Type 'quit' to exit.")
    print(f"Logged in as: {current_user.first_name} {current_user.last_name} ({current_user.username})")
    print("You can ask questions about your own data in natural language.")
    print(f"Your user ID is: {current_user.id}")
    
    while True:
        # Get user input
        user_input = input("\nYou: ").strip()
        
        if user_input.lower() == 'quit':
            print("Goodbye!")
            break
            
        try:
            # Process the input through the protected agent chain
            response_text = protected_agent.invoke({"input": user_input})
            
            # Get the AI's response
            ai_message = AIMessage(content=response_text)
            
            # Update chat history with the new exchange
            chat_history.append((HumanMessage(content=user_input), ai_message))
            
            # Print the response
            print(f"\nAI: {response_text}")
            
        except Exception as e:
            print(f"\nError: {str(e)}")
            print("Let's try that again.")

if __name__ == "__main__":
    main()
