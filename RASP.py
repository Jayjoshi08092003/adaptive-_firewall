import functools
import re

# 1. RASP DEFENSE LOGIC (The RASP Agent's Core)
# This is a highly simplified pattern matcher. In a real RASP, this would be a
# sophisticated ML model or internal policy check.
SQL_INJECTION_PATTERN = re.compile(r"(['\"])\s*(OR|or|--|#)\s+.*", re.IGNORECASE)

def rasp_policy_decorator(target_function):
    """
    Simulates a RASP agent monitoring a high-risk application function.
    It wraps the function and inspects its arguments before allowing execution.
    """
    @functools.wraps(target_function)
    def wrapper_rasp_policy(*args, **kwargs):
        # RASP Principle: Introspection of the arguments passed to the function
        
        # We assume the first positional argument is the user input (the 'data')
        if args:
            user_input = args[0] 
            
            # --- The RASP Decision Point ---
            if isinstance(user_input, str):
                if SQL_INJECTION_PATTERN.search(user_input):
                    # RASP Action: The input matches a known malicious pattern
                    # AND it is about to be used by a DANGEROUS function.
                    
                    print("\n🚨 RASP POLICY VIOLATION DETECTED!")
                    print(f"Function: {target_function.__name__} - Arg: '{user_input[:40]}...'")
                    
                    # BLOCK THE EXECUTION: Throw an exception or return an error
                    raise PermissionError("RASP Blocked: SQL Injection attempt detected at function execution layer.")
        
        # If the input is deemed safe in this context, allow the original function to run
        return target_function(*args, **kwargs)

    return wrapper_rasp_policy

# 2. THE PROTECTED APPLICATION CODE
# The RASP agent is integrated by placing the decorator on the vulnerable function.

class Database:
    def __init__(self):
        self.db_log = []
    
    # The RASP agent hooks onto the critical function
    @rasp_policy_decorator
    def execute_sql_query(self, user_provided_input):
        """A function that dangerously incorporates user input into an SQL query."""
        # This part of the code is only reached if the RASP policy allowed it.
        sql_command = f"SELECT * FROM users WHERE user_name = '{user_provided_input}';"
        self.db_log.append(sql_command)
        return f"Query executed successfully for: {user_provided_input}"

# 3. DEMONSTRATION OF RASP IN ACTION

app = Database()

print("--- 1. Benign/Safe Request (Allowed by RASP) ---")
try:
    # Safe input
    result = app.execute_sql_query("Alice")
    print(f"Result: {result}")
except PermissionError as e:
    print(f"RASP Blocked: {e}")

print("\n" + "="*50 + "\n")

print("--- 2. Malicious Request (Blocked by RASP) ---")
try:
    # Malicious SQL Injection payload that would bypass a simple WAF without context
    malicious_payload = "admin' OR 1=1 --" 
    result = app.execute_sql_query(malicious_payload)
    print(f"Result: {result}")
except PermissionError as e:
    print(f"RASP Blocked: {e}")

print("\n" + "="*50 + "\n")

print("--- 3. Clean Input to a Different Function (RASP Not Applied) ---")
def log_event(data):
    # This function is not decorated, so RASP is not monitoring it
    print(f"Event Logged: {data}")

# If we run the malicious payload on an unprotected function, it is allowed
log_event(malicious_payload)