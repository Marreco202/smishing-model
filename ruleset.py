import re

# Rule 1: URL/Link Detection
def rule1(text: str) -> int:
    """
    Checks if a text contains a URL/link.
    Returns 1 if a URL is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for URLs
        
    Returns:
        int: 1 if URL is found, 0 otherwise
    """
    # Comprehensive URL pattern to catch various formats
    # Including common TLDs, shortened URLs, and URLs without protocol
    url_pattern = re.compile(r'''
        (https?://)?                               # Optional protocol (http:// or https://)
        (www\.)?                                   # Optional www
        ([a-zA-Z0-9-]+\.)+                         # Domain name parts
        ([a-zA-Z]{2,63})                           # Top-level domain
        (/\S*)?                                    # Optional path
        |                                          # OR shortened URLs
        (bit\.ly|t\.co|goo\.gl|tinyurl\.com)/\S*  # Common URL shorteners
    ''', re.VERBOSE)
    
    # Check if the pattern is found in the text
    if url_pattern.search(text):
        return 1
    else:
        return 0
    

# Rule 2: Mathematical Symbols Detection
def rule2(text: str) -> int:
    """
    Checks if a text contains any mathematical symbols.
    Returns 1 if any mathematical symbol is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for mathematical symbols
        
    Returns:
        int: 1 if mathematical symbols are found, 0 otherwise
    """
    # Define a comprehensive set of mathematical symbols
    math_symbols = {
        # Basic arithmetic
        '+', '-', '*', '/', '=', 
        # Comparison
        '<', '>', '≤', '≥', '≠',
        # Other math symbols
        '±', '×', '÷', '∑', '∏', '√', '∛', 
        # Superscripts and subscripts commonly used in math
        '²', '³', '¹', '½', '¼', '¾',
        # Greek letters often used in mathematics
        'π', 'θ', 'Δ', 'Σ', 'Ω',
        # Other math-related symbols
        '∞', '∫', '∂', '∇', '∀', '∃', '∈', '∉', '∩', '∪'
    }
    
    # Check if any mathematical symbol is found in the text
    for symbol in math_symbols:
        if symbol in text:
            return 1
    
    # Also check for numeric expressions with operators using regex
    # This catches patterns like "2+2", "5*10", "100/2" etc.
    math_expression_pattern = re.compile(r'\d+\s*[+\-*/=]\s*\d+')
    if math_expression_pattern.search(text):
        return 1
    
    return 0


# Rule 3: Financial Symbols Detection
def rule3(text: str) -> int:
    """
    Checks if a text contains any financial symbols.
    Returns 1 if any financial symbol is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for financial symbols
        
    Returns:
        int: 1 if financial symbols are found, 0 otherwise
    """
    # Define common financial symbols
    financial_symbols = ['$', '£', '€', '¥', '₹', '¢']
    
    # Check if any financial symbol is in the text
    for symbol in financial_symbols:
        if symbol in text:
            return 1
    
    # Check for currency codes and financial terms using regex
    financial_patterns = [
        r'\b(USD|EUR|GBP|JPY|AUD|CAD|CHF|CNY|INR)\b',  # Common currency codes | ADICIONAR O REAL
        r'\b(dollar|euro|pound|yen|rupee|cent)[s]?\b',  # Currency names
        r'\b\d+(\.\d+)?\s*(dollars?|euros?|pounds?|yens?|rupees?)\b',  # Amount with currency name
        # r'\bmoney\s+back\b',  # Common financial phrases
        # r'\bcash\s+prize[s]?\b',
        # r'\bfree\s+cash\b'
    ]
    
    for pattern in financial_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return 1
    
    return 0



# Rule 4: Phone Number Detection
def rule4(text: str) -> int:
    """
    Checks if a text contains a mobile phone number.
    Returns 1 if a phone number is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for phone numbers
        
    Returns:
        int: 1 if phone number is found, 0 otherwise
    """
    # Various phone number patterns to match different formats
    phone_patterns = [
        # International format with country code (e.g., +1 123 456 7890, +44-7911-123456)
        r'(?:\+\d{1,3}[-\.\s]?)?\(?\d{1,4}\)?[-\.\s]?\d{1,4}[-\.\s]?\d{1,9}',
        
        # US/Canada format (e.g., (123) 456-7890, 123-456-7890)
        r'\(?\d{3}\)?[-\.\s]?\d{3}[-\.\s]?\d{4}',
        
        # UK format (e.g., 07911 123456, 07911-123-456)
        r'0\d{3}[-\.\s]?\d{3}[-\.\s]?\d{3,4}',
        
        # Generic formats with at least 10 digits
        r'\b\d{3}[-\.\s]?\d{3}[-\.\s]?\d{4}\b',
        
        # Format with separators (e.g., 123.456.7890)
        r'\d{3}[.\-]\d{3}[.\-]\d{4}',
        
        # Simple sequence of digits (e.g., 1234567890) - at least 10 digits but not more than 15
        r'\b\d{10,15}\b'
    ]
    
    # Check if any pattern matches the text
    for pattern in phone_patterns:
        if re.search(pattern, text):
            return 1
    
    return 0



# Rule 5: Suspicious Words Detection
def rule5(text: str) -> int:
    """
    Checks if a text contains suspicious words commonly used in scam or phishing messages.
    Returns 1 if any suspicious word is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for suspicious words
        
    Returns:
        int: 1 if suspicious words are found, 0 otherwise
    """
    # Convert text to lowercase for case-insensitive matching
    text_lower = text.lower()
    
    # Define suspicious word patterns by category
    suspicious_patterns = {
        # Financial incentives
        'financial': [
            r'\bfree\b', r'\bwin\b', r'\bwon\b', r'\bprize[s]?\b', r'\bcash\b', r'\bmoney\b', 
            r'\bgift[s]?\b', r'\bdiscount\b', r'\bbonus\b', r'\bclaim\b', r'\breward[s]?\b', 
            r'\bcredit[s]?\b', r'\brefund\b', r'\b\d+%\s+off\b', r'\bsave\s+\d+\b'
        ],
        
        # Urgency words
        'urgency': [
            r'\burgent\b', r'\bimmediate\b', r'\bquick\b', r'\blast\s+chance\b', 
            r'\blimited\s+time\b', r'\bexpires?\b', r'\bexpiring\b', r'\btoday\s+only\b', 
            r'\bact\s+now\b', r'\bhurry\b', r'\bdeadline\b', r'\btomorrow\b'
        ],
        
        # Account-related
        'account': [
            r'\baccount[s]?\b', r'\bpassword[s]?\b', r'\blogin\b', r'\bverify\b', r'\bsecurity\b', 
            r'\bupdate[s]?\b', r'\bconfirm\b', r'\bvalidate\b', r'\bauthenticate\b', r'\breset\b', 
            r'\bsuspended\b', r'\block[ed]?\b', r'\bdeactivate[d]?\b', r'\breactivate\b'
        ],
        
        # Official-sounding terms
        'official': [
            r'\bnotice\b', r'\balert[s]?\b', r'\bwarning[s]?\b', r'\bimportant\b', r'\bofficial\b', 
            r'\blegal\b', r'\bgovernment\b', r'\bbank\b', r'\btax[es]?\b', r'\bcompensation\b',
            r'\bauthority\b', r'\bagency\b', r'\bdepartment\b', r'\bpayment[s]?\b'
        ],
        
        # Call to action
        'action': [
            r'\bclick\b', r'\bfollow\b', r'\bcall\b', r'\bregister\b', r'\bsubscribe\b', r'\bapply\b',
            r'\bdownload\b', r'\bsubmit\b', r'\breply\b', r'\brespond\b', r'\bcomplete\b', r'\bvisit\b',
            r'\bcheck\b', r'\blink\b', r'\burl\b', r'\bwebsite\b', r'\binfo[rmation]?\b'
        ],
        
        # Pressure tactics
        'pressure': [
            r'\bonly\b', r'\bselected\b', r'\bchosen\b', r'\bexclusive\b', r'\bspecial\b',
            r'\blucky\b', r'\bchance\b', r'\bopportunity\b', r'\brisk\b', r'\bproblem\b',
            r'\bnow\b', r'\btoday\b', r'\blast\b', r'\bone\s+time\b', r'\bfinal\b'
        ],
        
        # Common scam phrases
        'scam_phrases': [
            r'\byou\s+have\s+won\b', r'\bcongratulations\b', r'\blottery\b', r'\bprize\s+draw\b',
            r'\bunclaimed\b', r'\bunique\s+offer\b', r'\bexclusive\s+deal\b', r'\bverify\s+your\s+identity\b',
            r'\baccess\s+denied\b', r'\baccount\s+suspended\b', r'\bsecurity\s+breach\b',
            r'\blimited\s+offer\b', r'\bfree\s+money\b', r'\bguaranteed\s+results\b'
        ],

        # Common scam phrases from paper
        'paper_phrases': [
            r'\bfree\b', r'\baccident\b', r'\bawards\b', r'\bdating\b', r'\bwon\b', r'\bservice\b',
            r'\blottery\b',r'\bmins\b',r'\bfree\b',r'\bvisit\b',r'\bdelivery\b',r'\bcash\b',r'\bclaim\b',r'\bprize\b',
            r'\bdelivery\b'
        ]
    }
    
    # Check for suspicious patterns in text
    for category, patterns in suspicious_patterns.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                return 1
    
    # Look for combinations of suspicious elements
    # These are more indicative when found together
    combinations = [
        # Urgency + financial
        (r'\b(urgent|quick|hurry|now)\b.*\b(free|money|cash|prize|win)\b', 
         r'\b(free|money|cash|prize|win)\b.*\b(urgent|quick|hurry|now)\b'),
         
        # Action + account
        (r'\b(click|call|reply)\b.*\b(account|password|login|verify)\b',
         r'\b(account|password|login|verify)\b.*\b(click|call|reply)\b'),
         
        # Financial + pressure
        (r'\b(money|cash|free|win)\b.*\b(only|exclusive|special|chance)\b',
         r'\b(only|exclusive|special|chance)\b.*\b(money|cash|free|win)\b')
    ]
    
    for pair in combinations:
        if re.search(pair[0], text_lower) or re.search(pair[1], text_lower):
            return 1
    
    return 0



# Rule 6: Message Length Detection
def rule6(text: str) -> int:
    """
    Checks if a text message is longer than a threshold length.
    Returns 1 if the message is considered too long, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for length
        
    Returns:
        int: 1 if text is too long, 0 otherwise
    """
    # Define threshold for message length (150 characters)
    # SMS smishing attempts often use longer messages to make sophisticated scams
    threshold_length = 150
    
    # Check if the message length exceeds the threshold
    if len(text) > threshold_length:
        return 1
    else:
        return 0
    


# Rule 7: Self-Answering Patterns Detection
def rule7(text: str) -> int:
    """
    Checks if a text contains self-answering patterns, which are common in smishing attempts.
    These patterns include text that asks a question and immediately provides an answer,
    or uses rhetorical questions to manipulate the recipient.
    
    Parameters:
        text (str): The input text to check for self-answering patterns
        
    Returns:
        int: 1 if self-answering patterns are found, 0 otherwise
    """
    # Convert to lowercase for case-insensitive matching
    text_lower = text.lower()
    
    # Define patterns for self-answering techniques
    self_answering_patterns = [
        # Question followed by immediate answer
        r'\b(did you|have you|are you|would you|could you|do you).*\?\s*yes',
        r'\b(did you|have you|are you|would you|could you|do you).*\?\s*no',
        
        # Rhetorical questions used to lead recipient
        r'(want to|looking to|interested in|need to).*\?',
        r'(wondering|curious|thinking) (about|if|whether).*\?',
        
        # False choices - presenting limited options
        r'(reply|text|send) (yes|no|y|n|1|2|stop|start)',
        r'choose (between|from)',
        
        # Self-answering statements
        r'you\'re (probably|likely|surely) (wondering|asking|thinking)',
        r'i know (you|what you|that you)',
        
        # False assumptions that imply consent
        r'as (requested|you asked|you wanted)',
        r'(per|following|based on) your (request|inquiry|interest)',
        
        # Leading questions with implied answers
        r'who (doesn\'t|wouldn\'t) want',
        r'isn\'t it time',
        r'why not',
        
        # Fake response requirements
        r'(text|reply|send|call|sms) \w+ to (claim|get|receive|stop|confirm)'
    ]
    
    # Check if any of the patterns exist in the text
    for pattern in self_answering_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    # Look for question-answer pairs (question mark followed by answer)
    question_answer_pattern = r'\?[^?!.]{1,30}(yes|no|absolutely|definitely|of course|sure|certainly)'
    if re.search(question_answer_pattern, text_lower):
        return 1
    
    return 0

# Rule 8: Visual Morphemes Detection
def rule8(text: str) -> int:
    """
    Checks if a text contains visual morphemes - characters, symbols, or formatting 
    that can be used to visually mislead recipients in smishing attacks.
    
    Parameters:
        text (str): The input text to check for visual morphemes
        
    Returns:
        int: 1 if visual morphemes are found, 0 otherwise
    """
    # Convert to lowercase for consistent pattern matching
    # (but keep a copy of original text for case-based patterns)
    text_lower = text.lower()
    
    # 1. Check for excessive use of uppercase (shouting)
    uppercase_ratio = sum(1 for c in text if c.isupper()) / len(text) if len(text) > 0 else 0
    if uppercase_ratio > 0.3 and len(text) > 5:  # If more than 30% of characters are uppercase
        return 1
    
    # 2. Check for repeated punctuation (emphasis or attention-grabbing)
    repeated_punctuation_patterns = [
        r'[!]{2,}',      # Multiple exclamation marks
        r'[?]{2,}',      # Multiple question marks
        r'[.]{3,}',      # Ellipsis with many dots
        r'[!?]{2,}',     # Mixed exclamation and question marks
        r'[$£€¥₹¢]{2,}'  # Repeated currency symbols
    ]
    
    for pattern in repeated_punctuation_patterns:
        if re.search(pattern, text):
            return 1
    
    # 3. Check for unusual character substitution (l33t speak or similar)
    substitution_patterns = [
        r'\b\w*[0-9]+\w*[a-zA-Z]+\w*\b',  # Numbers mixed with letters in a word
        r'\b\w*[a-zA-Z]+\w*[0-9]+\w*\b',  # Letters mixed with numbers in a word
        r'\b[a-zA-Z0-9]*[@$&*]+[a-zA-Z0-9]*\b'  # Special characters embedded in words
    ]
    
    for pattern in substitution_patterns:
        if re.search(pattern, text) and not re.search(r'\b(https?://|www\.)\S+', text):  # Exclude URLs
            return 1
    
    # 4. Check for excessive spacing or formatting
    spacing_patterns = [
        r'(\s{2,})',     # Multiple spaces
        r'([_-]{2,})'    # Multiple underscores or hyphens used for formatting
    ]
    
    for pattern in spacing_patterns:
        if len(re.findall(pattern, text)) > 2:  # More than 2 instances of unusual spacing
            return 1
    
    # 5. Check for unusual Unicode characters that mimic regular letters
    # These are often used to bypass filters
    suspicious_unicode_patterns = [
        r'[\u00A0-\u00FF]',  # Latin-1 Supplement
        r'[\u0400-\u04FF]',  # Cyrillic
        r'[\u0370-\u03FF]',  # Greek
        r'[\u2000-\u206F]',  # General Punctuation
        r'[\u2070-\u209F]',  # Superscripts and Subscripts
        r'[\u20A0-\u20CF]',  # Currency Symbols
        r'[\u2100-\u214F]'   # Letterlike Symbols
    ]
    
    # Only flag if there's a mix of ASCII and non-ASCII characters
    has_ascii = bool(re.search(r'[a-zA-Z]', text))
    has_suspicious_unicode = any(bool(re.search(pattern, text)) for pattern in suspicious_unicode_patterns)
    
    if has_ascii and has_suspicious_unicode:
        return 1
    
    # 6. Check for patterns that create visual attention
    visual_attention_patterns = [
        r'(\*\*|\*|\#|\=\=|\=){2,}[^*#=]+\1{2,}',  # Text surrounded by asterisks or other markers
        r'[A-Z]{3,}',                               # All caps words (3+ letters)
        r'(?<!\w)([A-Z][a-z]*){3,}(?!\w)'          # CamelCase with 3+ words
    ]
    
    for pattern in visual_attention_patterns:
        if re.search(pattern, text):
            return 1
    
    # 7. Check for excessive use of emojis or emoticons
    emoji_patterns = [
        r'(?::|;|=)(?:-)?(?:\)|D|P|p|\()',  # Basic emoticons
        r'[\U0001F600-\U0001F64F]',         # Emoticons Unicode block
        r'[\U0001F300-\U0001F5FF]',         # Miscellaneous Symbols and Pictographs
        r'[\U0001F680-\U0001F6FF]',         # Transport and Map Symbols
        r'[\U0001F700-\U0001F77F]',         # Alchemical Symbols
        r'[\U0001F780-\U0001F7FF]',         # Geometric Shapes
        r'[\U0001F800-\U0001F8FF]',         # Supplemental Arrows-C
        r'[\U0001F900-\U0001F9FF]',         # Supplemental Symbols and Pictographs
        r'[\U0001FA00-\U0001FA6F]'          # Chess Symbols
    ]
    
    emoji_count = 0
    for pattern in emoji_patterns:
        emoji_count += len(re.findall(pattern, text))
    
    if emoji_count > 3:  # More than 3 emojis in a message
        return 1
        
    return 0


# Rule 9: Email Address Detection
def rule9(text: str) -> int:
    """
    Checks if a text contains an email address.
    Returns 1 if an email address is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for email addresses
        
    Returns:
        int: 1 if email address is found, 0 otherwise
    """
    # Comprehensive email pattern to catch various formats
    # This pattern supports:
    # - Standard emails (user@domain.com)
    # - Emails with numbers in username or domain
    # - Emails with dots, underscores, hyphens, and plus signs in username
    # - Various TLDs (com, net, org, edu, etc.)
    # - Subdomains
    
    email_pattern = re.compile(r'''
        \b[a-zA-Z0-9._%+-]+            # Username part
        @                              # @ symbol
        [a-zA-Z0-9.-]+                 # Domain name
        \.[a-zA-Z]{2,63}               # TLD (.com, .org, etc.)
        \b
    ''', re.VERBOSE)
    
    # Check if the pattern is found in the text
    if email_pattern.search(text):
        return 1
    else:
        return 0