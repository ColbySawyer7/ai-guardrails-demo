import os
from typing import List, Tuple, Any, Dict, Optional
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough, RunnableSequence
import sqlite3
from dataclasses import dataclass
from enum import Enum
import re

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

def get_db_connection() -> sqlite3.Connection:
    """Get a connection to the SQLite database."""
    return sqlite3.connect("users.db")

def create_sql_verification_chain() -> RunnableSequence:
    """Create a chain that verifies SQL queries for potential injection attacks."""
    llm = ChatOpenAI(
        base_url="https://openrouter.ai/api/v1",
        model="gpt-3.5-turbo",
        temperature=0,
        streaming=True
    )

    sql_verification_prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content="""You are a SQL security verification system that checks SQL queries for potential injection attacks and malicious patterns.
        
        Your job is to analyze SQL queries and return a response in EXACTLY this format:
        safe: true/false
        reason: <explanation>
        suggested_query: <safe alternative query if applicable>

        Rules for SQL safety:
        1. Only allow SELECT queries
        2. No UNION, JOIN, or subqueries that could expose other users' data
        3. No string concatenation or dynamic SQL
        4. No OR conditions that could bypass WHERE clauses
        5. No LIKE patterns that could match multiple users
        6. No functions that could be used maliciously (e.g., substr, instr)
        7. Must include proper WHERE clause restrictions
        8. No attempts to access system tables or metadata
        9. No attempts to modify data (INSERT, UPDATE, DELETE)
        10. No attempts to create or drop tables

        Examples of unsafe queries:
        - "SELECT * FROM users WHERE id = 1 OR 1=1"
        - "SELECT * FROM users WHERE first_name LIKE '%'"
        - "SELECT * FROM users UNION SELECT * FROM users"
        - "SELECT * FROM users WHERE id = (SELECT id FROM users LIMIT 1)"
        - "SELECT * FROM users WHERE address LIKE '%' || (SELECT address FROM users WHERE id = 2) || '%'"

        Examples of safe queries:
        - "SELECT first_name, last_name FROM users WHERE id = 1"
        - "SELECT address FROM users WHERE id = 1"
        - "SELECT phone_number FROM users WHERE id = 1"

        Example response for unsafe query "SELECT * FROM users WHERE id = 1 OR 1=1":
        safe: false
        reason: Query contains OR condition that could bypass WHERE clause
        suggested_query: SELECT first_name, last_name FROM users WHERE id = 1

        Example response for safe query "SELECT address FROM users WHERE id = 1":
        safe: true
        reason: Query is properly restricted to a single user
        suggested_query: null"""),
        ("human", "SQL Query to verify: {query}")
    ])

    def parse_verification_response(response: str) -> Dict[str, Any]:
        """Parse the SQL verification response into a structured format."""
        try:
            # Debug print
            print("\nSQL Verification Response:")
            print(response)
            print("---")

            # Initialize default values
            result = {
                "safe": False,
                "reason": "Invalid response format",
                "suggested_query": None
            }

            # Parse each line
            for line in response.split('\n'):
                line = line.strip().lower()
                if not line:
                    continue
                
                if line.startswith('safe:'):
                    result["safe"] = 'true' in line
                elif line.startswith('reason:'):
                    result["reason"] = line.replace('reason:', '').strip()
                elif line.startswith('suggested_query:'):
                    query = line.replace('suggested_query:', '').strip()
                    if query and query.lower() != 'null':
                        result["suggested_query"] = query

            return result
        except Exception as e:
            print(f"Error parsing verification response: {e}")
            return {
                "safe": False,
                "reason": f"Error parsing response: {str(e)}",
                "suggested_query": None
            }

    return (
        {"query": RunnablePassthrough()}
        | sql_verification_prompt
        | llm
        | StrOutputParser()
        | parse_verification_response
    )

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
        - No queries that could expose other users' data
        - No queries about finding neighbors or similar users
        
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
        - "Find users who live near me" (could expose other users' data)
        - "Who are my neighbors?" (could expose other users' data)
        - "Find users in the same city" (could expose other users' data)

        Example response for "What's my address?":
        authorized: true
        reason: User is requesting their own address
        sensitive_fields: []
        sql_query: SELECT address FROM users WHERE id = {current_user.id}

        Example response for "Find users who live near me":
        authorized: false
        reason: Query could expose other users' data
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

def create_agent() -> AgentExecutor:
    # Initialize the language model
    llm = ChatOpenAI(
        base_url="https://openrouter.ai/api/v1",
        model="gpt-3.5-turbo",
        temperature=0,
        streaming=True
    )

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
    If a name search returns no results, try using partial matches with LIKE."""

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

    return agent_executor

def create_output_guardrail_chain(current_user: User) -> RunnableSequence:
    """Create a chain that sanitizes and verifies output before returning to the user."""
    llm = ChatOpenAI(
        base_url="https://openrouter.ai/api/v1",
        model="gpt-3.5-turbo",
        temperature=0,
        streaming=True
    )

    output_guardrail_prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=f"""You are a security output guardrail system that sanitizes and verifies responses before they are shown to users.
        Current user: {current_user.first_name} {current_user.last_name} (ID: {current_user.id})
        
        Your job is to:
        1. Analyze the response for any sensitive information
        2. Verify that the response only contains data for the current user
        3. Sanitize any sensitive data that shouldn't be exposed
        4. Return a response in EXACTLY this format:
        safe: true/false
        reason: <explanation>
        sanitized_response: <modified response if needed>
        original_response: <original response for logging>

        Rules for output safety:
        1. Never expose SSN numbers (replace with "REDACTED")
        2. Never expose other users' data
        3. Never expose full addresses (only city and state)
        4. Never expose full phone numbers (only last 4 digits)
        5. Never expose full dates of birth (only year)
        6. Never expose full email addresses (only username part)
        7. Never expose any data that could be used for identity theft
        8. Never expose any data that could be used to find other users
        9. Never expose any data that could be used to bypass security
        10. Always verify that data belongs to the current user

        Examples of unsafe responses:
        - "Your SSN is 123-45-6789" -> "Your SSN is REDACTED"
        - "Your full address is 123 Main St, Anytown, CA 12345" -> "You live in Anytown, CA"
        - "Your phone number is (555) 123-4567" -> "Your phone number ends in 4567"
        - "Your date of birth is 1990-01-01" -> "You were born in 1990"
        - "Your email is john.doe@example.com" -> "Your email username is john.doe"

        Example response for unsafe output:
        safe: false
        reason: Response contains full SSN number
        sanitized_response: Your SSN is REDACTED
        original_response: Your SSN is 123-45-6789

        Example response for safe output:
        safe: true
        reason: Response contains only non-sensitive data
        sanitized_response: Your name is John Doe
        original_response: Your name is John Doe"""),
        ("human", "Response to verify: {response}")
    ])

    def parse_output_guardrail_response(response: str) -> Dict[str, Any]:
        """Parse the output guardrail response into a structured format."""
        try:
            # Debug print
            print("\nOutput Guardrail Response:")
            print(response)
            print("---")

            # Initialize default values
            result = {
                "safe": False,
                "reason": "Invalid response format",
                "sanitized_response": None,
                "original_response": None
            }

            # Parse each line
            for line in response.split('\n'):
                line = line.strip().lower()
                if not line:
                    continue
                
                if line.startswith('safe:'):
                    result["safe"] = 'true' in line
                elif line.startswith('reason:'):
                    result["reason"] = line.replace('reason:', '').strip()
                elif line.startswith('sanitized_response:'):
                    sanitized = line.replace('sanitized_response:', '').strip()
                    if sanitized and sanitized.lower() != 'null':
                        result["sanitized_response"] = sanitized
                elif line.startswith('original_response:'):
                    original = line.replace('original_response:', '').strip()
                    if original and original.lower() != 'null':
                        result["original_response"] = original

            return result
        except Exception as e:
            print(f"Error parsing output guardrail response: {e}")
            return {
                "safe": False,
                "reason": f"Error parsing response: {str(e)}",
                "sanitized_response": None,
                "original_response": None
            }

    return (
        {"response": RunnablePassthrough()}
        | output_guardrail_prompt
        | llm
        | StrOutputParser()
        | parse_output_guardrail_response
    )

def main():
    # Get a random user for this session
    current_user = get_random_user()
    if not current_user:
        print("Error: Could not get a user from the database. Please ensure the database is populated.")
        return

    # Create the agent and all guardrail chains
    agent_executor = create_agent()
    guardrail_chain = create_guardrail_chain(current_user)
    sql_verification_chain = create_sql_verification_chain()
    output_guardrail_chain = create_output_guardrail_chain(current_user)
    
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
            # First, run the guardrail check
            guardrail_result = guardrail_chain.invoke(user_input)
            
            if not guardrail_result["authorized"]:
                print(f"\nAccess Denied: {guardrail_result['reason']}")
                if guardrail_result["sensitive_fields"]:
                    print(f"Sensitive fields detected: {', '.join(guardrail_result['sensitive_fields'])}")
                continue
            
            # If authorized and we have a SQL query, verify it
            if guardrail_result["sql_query"]:
                # Replace the user ID placeholder with the actual ID
                sql_query = guardrail_result["sql_query"].format(current_user=current_user)
                
                # Verify the SQL query
                verification_result = sql_verification_chain.invoke(sql_query)
                
                if not verification_result["safe"]:
                    print(f"\nSQL Query Blocked: {verification_result['reason']}")
                    if verification_result["suggested_query"]:
                        print(f"Suggested safe query: {verification_result['suggested_query']}")
                    continue
                
                # If the query is safe, execute it
                raw_response = query_database.invoke(sql_query)
                
                # Run the output through the output guardrail
                output_result = output_guardrail_chain.invoke(raw_response)
                
                if not output_result["safe"]:
                    print(f"\nOutput Sanitized: {output_result['reason']}")
                    print(f"AI: {output_result['sanitized_response']}")
                else:
                    print(f"\nAI: {output_result['sanitized_response']}")
                continue
            
            # If no SQL query was generated, proceed with the agent
            raw_response = agent_executor.invoke({
                "input": user_input,
                "chat_history": [msg for pair in chat_history for msg in pair]
            })
            
            # Run the agent's response through the output guardrail
            output_result = output_guardrail_chain.invoke(raw_response["output"])
            
            # Get the AI's response (either sanitized or original if safe)
            ai_message = AIMessage(content=output_result["sanitized_response"] if not output_result["safe"] else raw_response["output"])
            
            # Update chat history with the new exchange
            chat_history.append((HumanMessage(content=user_input), ai_message))
            
            # Print the response
            if not output_result["safe"]:
                print(f"\nOutput Sanitized: {output_result['reason']}")
            print(f"\nAI: {ai_message.content}")
            
        except Exception as e:
            print(f"\nError: {str(e)}")
            print("Let's try that again.")

if __name__ == "__main__":
    main() 