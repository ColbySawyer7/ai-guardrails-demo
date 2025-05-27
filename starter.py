import os
from typing import List, Tuple, Any
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
import sqlite3

# Load environment variables
load_dotenv()

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

@tool
def get_weather(location: str) -> str:
    """Get the current weather in a given location."""
    # This is a mock implementation - in a real app, you'd call a weather API
    return f"The weather in {location} is sunny and 72°F"

@tool
def search_web(query: str) -> str:
    """Search the web for information about a topic."""
    # This is a mock implementation - in a real app, you'd use a search API
    return f"Here are some search results about {query}"

def create_agent() -> AgentExecutor:
    # Initialize the language model
    llm = ChatOpenAI(
        base_url="https://openrouter.ai/api/v1",
        model="gpt-3.5-turbo",
        temperature=0,
        streaming=True
    )

    # Define the tools
    tools = [query_database, get_weather, search_web]

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
    You can access any user's data in the database.
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

    return agent_executor

def main():
    # Create the agent
    agent_executor = create_agent()
    
    # Initialize chat history as a list of messages
    chat_history: List[Tuple[HumanMessage, AIMessage]] = []
    
    print("Welcome to the AI Assistant! Type 'quit' to exit.")
    print("WARNING: This version has no guardrails - all user data is accessible!")
    print("You can ask questions about any user's data in natural language.")
    
    while True:
        # Get user input
        user_input = input("\nYou: ").strip()
        
        if user_input.lower() == 'quit':
            print("Goodbye!")
            break
            
        try:
            # Process the query directly with the agent
            response = agent_executor.invoke({
                "input": user_input,
                "chat_history": [msg for pair in chat_history for msg in pair]
            })
            
            # Get the AI's response
            ai_message = AIMessage(content=response["output"])
            
            # Update chat history with the new exchange
            chat_history.append((HumanMessage(content=user_input), ai_message))
            
            # Print the response
            print(f"\nAI: {ai_message.content}")
            
        except Exception as e:
            print(f"\nError: {str(e)}")
            print("Let's try that again.")

if __name__ == "__main__":
    main() 