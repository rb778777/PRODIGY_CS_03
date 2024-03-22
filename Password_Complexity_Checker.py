import re

def assess_password_strength(password):
    
    length_criteria = len(password) >= 8
    uppercase_criteria = any(char.isupper() for char in password)
    lowercase_criteria = any(char.islower() for char in password)
    digit_criteria = any(char.isdigit() for char in password)
    special_char_criteria = bool(re.search(r'[\W_]', password)) 

    
    strength_score = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, special_char_criteria])

    
    if strength_score == 5:
        return "Your password is very strong!"
    elif strength_score >= 4:
        suggestions = []
        if not digit_criteria:
            suggestions.append("Add at least one digit (0-9).")
        if not special_char_criteria:
            suggestions.append("Add at least one special character.")
        if len(password) < 12:
            suggestions.append("Increase the length of your password to at least 12 characters.")
        if not uppercase_criteria:
            suggestions.append("Use at least one capital letter (A-Z).")
        return f"Your password is strong, but could be improved.\nSuggestions:\n" + "\n".join(suggestions)
    elif strength_score >= 2:
        suggestions = []
        if not uppercase_criteria:
            suggestions.append("Add at least one uppercase letter (A-Z).")
        if not lowercase_criteria:
            suggestions.append("Add at least one lowercase letter (a-z).")
        if not digit_criteria:
            suggestions.append("Add at least one digit (0-9).")
        if not special_char_criteria:
            suggestions.append("Add at least one special character.")
        if len(password) < 12:
            suggestions.append("Increase the length of your password to at least 12 characters.")
        return f"Your password is moderate.\nSuggestions:\n" + "\n".join(suggestions)
    elif strength_score >= 1:
        suggestions = []
        if not uppercase_criteria:
            suggestions.append("Add at least one uppercase letter (A-Z).")
        if not lowercase_criteria:
            suggestions.append("Add at least one lowercase letter (a-z).")
        if not digit_criteria:
            suggestions.append("Add at least one digit (0-9).")
        if not special_char_criteria:
            suggestions.append("Add at least one special character.")
        if len(password) < 8:
            suggestions.append("Increase the length of your password to at least 8 characters.")
        return f"Your password is weak.\nSuggestions:\n" + "\n".join(suggestions)
    else:
        suggestions = []
        if not uppercase_criteria:
            suggestions.append("Add at least one uppercase letter (A-Z).")
        if not lowercase_criteria:
            suggestions.append("Add at least one lowercase letter (a-z).")
        if not digit_criteria:
            suggestions.append("Add at least one digit (0-9).")
        if not special_char_criteria:
            suggestions.append("Add at least one special character.")
        if len(password) < 8:
            suggestions.append("Increase the length of your password to at least 8 characters.")
        return f"Your password is very weak.\nSuggestions:\n" + "\n".join(suggestions)

def main():
    password = input("Enter your password: ")
    strength_feedback = assess_password_strength(password)
    print(strength_feedback)

if __name__ == "__main__":
    main()
