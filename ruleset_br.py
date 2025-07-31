import re
import phonenumbers
from phonenumbers import PhoneNumberMatcher

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
    
    suspicious_url_patterns = [
        r'bit\.ly/[a-zA-Z0-9]{6,}',     # URLs encurtadas genéricas
        r'tinyurl\.com/[a-zA-Z0-9]+',   # TinyURL genérico
        r'https?://\d+\.\d+\.\d+\.\d+', # IPs diretos
        r'[a-z]+-[a-z]+-[a-z]+\.com',   # Domínios com muitos hífens
    ]

    # Check if the pattern is found in the text
    if url_pattern.search(text):
        return 1
    
    # Check for suspicious URL patterns
    for pattern in suspicious_url_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return 1
    
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
    # Define common financial symbols including Brazilian ones
    financial_symbols = ['$', '£', '€', '¥', '₹', '¢', 'R$']
    
    # Check if any financial symbol is in the text
    for symbol in financial_symbols:
        if symbol in text:
            return 1
    
    # Check for currency codes and financial terms using regex
    financial_patterns = [
        r'\b(USD|EUR|GBP|JPY|AUD|CAD|CHF|CNY|INR|BRL)\b',  # Common currency codes including Brazilian Real
        r'\b(dollar|euro|pound|yen|rupee|cent|real|reais)[s]?\b',  # Currency names including Portuguese
        r'\b\d+(\.\d+|,\d+)?\s*(dollars?|euros?|pounds?|yens?|rupees?|reais?|centavos?)\b',  # Amount with currency name
        r'\bR\$\s*\d+(\.\d{3})*(,\d{2})?\b',  # Brazilian Real format (R$ 1.000,00)
        r'\b\d+(\.\d{3})*(,\d{2})?\s*reais?\b',  # Amount in reais
        r'\b\d+(\.\d{3})*(,\d{2})?\s*R\$\b',  # Alternative Real format
    ]
    
    for pattern in financial_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return 1
    
    return 0


''
def rule4(text: str) -> int:
    """
    Checks if a text contains Brazilian phone numbers.
    Returns 1 if an Brazilian phone number is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for Brazilian phone numbers
        
    Returns:
        int: 1 if Brazilian phone number is found, 0 otherwise
    """
    # Brazilian mobile phone number patterns
    # Mobile numbers in Brazil start with 9 and have the format:
    # National: (XX) 9XXXX-XXXX or (XX) 9 XXXX-XXXX
    # International: +55 XX 9XXXX-XXXX or +55 XX 9 XXXX-XXXX
    # Where XX is the area code (11-99)
    
    brazilian_patterns = [
        # International format: +55 XX 9XXXX-XXXX or +55 (XX) 9XXXX-XXXX
        r'\+55[-\.\s]?\(?(?:1[1-9]|[2-9][0-9])\)?[-\.\s]?9[-\.\s]?\d{4}[-\.\s]?\d{4}',
        
        # National format with parentheses: (XX) 9XXXX-XXXX or (XX) 9 XXXX-XXXX
        r'\((?:1[1-9]|[2-9][0-9])\)[-\.\s]?9[-\.\s]?\d{4}[-\.\s]?\d{4}',
        
        # National format without parentheses: XX 9XXXX-XXXX or XX 9 XXXX XXXX
        r'\b(?:1[1-9]|[2-9][0-9])[-\.\s]?9[-\.\s]?\d{4}[-\.\s]?\d{4}\b',
        
        # Compact format: XX9XXXXXXXX (11 digits starting with area code)
        r'\b(?:1[1-9]|[2-9][0-9])9\d{8}\b',
        
        # Format with only mobile number: 9XXXX-XXXX or 9 XXXX XXXX (9 digits)
        r'\b9[-\.\s]?\d{4}[-\.\s]?\d{4}\b'
    ]

    # Check Brazilian patterns
    for pattern in brazilian_patterns:
        if re.search(pattern, text):
            return 1    
    return 0




# Rule 5: Financial Incentive Words Detection
def rule5(text: str) -> int:
    """
    Checks if a text contains financial incentive words commonly used in scam messages.
    Returns 1 if any financial incentive word is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for financial incentive words
        
    Returns:
        int: 1 if financial incentive words are found, 0 otherwise
    """
    text_lower = text.lower()
    
    financial_patterns = [
        r'\bgratuito\b', r'\bgrátis\b', r'\bganhar\b', r'\bganhou\b', r'\bprêmio[s]?\b', 
        r'\bdinheiro\b', r'\bpresente[s]?\b', r'\bdesconto\b', r'\bbônus\b', r'\breivindicar\b', 
        r'\brecompensa[s]?\b', r'\bcrédito[s]?\b', r'\breembolso\b', r'\bpix\b', r'\btransferência\b',
        r'\b\d+%\s+de\s+desconto\b', r'\beconomize\s+\d+\b', r'\bsortudo\b', r'\bsorteio\b'
    ]
    
    for pattern in financial_patterns:
        if re.search(pattern, text_lower):
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
    
    threshold_length = 200
    
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
    Adapted for Brazilian Portuguese context.
    
    Parameters:
        text (str): The input text to check for self-answering patterns
        
    Returns:
        int: 1 if self-answering patterns are found, 0 otherwise
    """
    # Convert to lowercase for case-insensitive matching
    text_lower = text.lower()
    
    # Define patterns for self-answering techniques (Brazilian Portuguese)
    self_answering_patterns = [
        # Question followed by immediate answer (Portuguese)
        r'\b(você|voce) (quer|precisa|tem|está|esta|gostaria|poderia).*\?\s*(sim|não|nao|claro|óbvio)',
        r'\b(já|ja) (tentou|viu|ouviu|conhece|sabe).*\?\s*(sim|não|nao|claro)',
        
        # Rhetorical questions used to lead recipient (Portuguese)
        r'(quer|precisa|interessado|interessada|procurando|buscando).*\?',
        r'(pensando|imaginando|curioso|curiosa) (sobre|se|em).*\?',
        r'(sabia|sabiam) que.*\?',
        r'por que (não|nao).*\?',
        r'quem (não|nao) (quer|gostaria).*\?',
        
        # False choices - presenting limited options (Portuguese)
        r'(responda|envie|mande|digite) (sim|não|nao|s|n|1|2|pare|stop)',
        r'escolha (entre|dentre)',
        r'digite (1|2|3) para',
        
        # Self-answering statements (Portuguese)
        r'você (provavelmente|certamente|deve estar) (pensando|se perguntando)',
        r'(eu sei|sabemos) (que você|o que você)',
        r'tenho certeza (que|de que)',
        
        # False assumptions that imply consent (Portuguese)
        r'conforme (solicitado|pedido|requisitado)',
        r'(conforme|seguindo|baseado em) (sua|seu) (solicitação|pedido|interesse)',
        r'você (pediu|solicitou|requisitou)',
        
        # Leading questions with implied answers (Portuguese)
        r'quem (não|nao) (quer|gostaria)',
        r'(não|nao) (é|eh) hora de',
        r'por que (não|nao)',
        r'(não|nao) seria (bom|ótimo|otimo|melhor)',
        
        # Fake response requirements (Portuguese)
        r'(envie|mande|digite|responda|ligue) \w+ para (receber|ganhar|parar|confirmar|reivindicar)',
        r'responda com (sim|não|nao|s|n) para',
        
        # Brazilian-specific patterns
        r'você (ganhou|foi selecionado|foi escolhido).*\?',
        r'(parabéns|felicidades).*você.*\?',
        r'(quer|gostaria de) (receber|ganhar) (dinheiro|prêmio|presente).*\?',
        r'sua (conta|cpf|cartão|cartao) (foi|está|esta).*\?',
        r'(confirme|valide|atualize) (seus dados|sua conta|seu cpf).*\?',
        
        # Common Brazilian scam question patterns
        r'(precisa|quer|gostaria) de (empréstimo|crédito|dinheiro).*\?',
        r'(nome sujo|cpf irregular|score baixo).*\?',
        r'(limpar nome|aumentar score|crédito aprovado).*\?',
        
        # Padrões muito brasileiros
        r'(manda|envia|digita) (seu\s+)?(cpf|rg|nome\s+completo)',
        r'(precisa|quer|tem\s+interesse) (em\s+)?(empréstimo|crédito)',
        r'(nome\s+sujo|score\s+baixo|cpf\s+irregular).*\?',
        r'(já\s+|ja\s+)?(consultou|verificou) (seu\s+)?(cpf|score|nome)',
        
        # Golpes de relacionamento (muito comuns)
        r'(você\s+é\s+|voce\s+eh\s+)?(solteiro|solteira|casado|casada)',
        r'(procurando|buscando) (relacionamento|namorar|casar)',
        r'(homem|mulher) (interessante|atraente|carinhoso|carinhosa)',
        
        # Padrões PIX e transferências
        r'(manda|envia) (pix|transferência) para',
        r'(chave\s+pix|dados\s+bancários) (seu|sua)',
        r'(receber|fazer) (pix|transferência).*\?'
    ]
    
    # Check if any of the patterns exist in the text
    for pattern in self_answering_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    # Look for question-answer pairs (question mark followed by answer) - Portuguese
    question_answer_pattern = r'\?[^?!.]{1,30}(sim|não|nao|absolutamente|definitivamente|claro|com certeza|certamente|óbvio|obvio)'
    if re.search(question_answer_pattern, text_lower):
        return 1
    
    # Check for Brazilian-specific response patterns
    brazilian_response_patterns = [
        r'(responda|digite|envie) (s|n|sim|não|nao|1|2|3) (para|pra)',
        r'(confirme|valide) (digitando|enviando|respondendo)',
        r'(clique|acesse|visite).*para (confirmar|validar|reivindicar)'
    ]
    
    for pattern in brazilian_response_patterns:
        if re.search(pattern, text_lower):
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
    

# Rule 10: Urgency Words Detection
def rule10(text: str) -> int:
    """
    Checks if a text contains urgency words that create pressure.
    Returns 1 if any urgency word is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for urgency words
        
    Returns:
        int: 1 if urgency words are found, 0 otherwise
    """
    text_lower = text.lower()
    
    urgency_patterns = [
        r'\burgente\b', r'\bimediato\b', r'\brápido\b', r'\búltima\s+chance\b', r'\búltima\s+oportunidade\b',
        r'\btempo\s+limitado\b', r'\bexpira\b', r'\bexpirando\b', r'\bvence\b', r'\bvencendo\b',
        r'\bsó\s+hoje\b', r'\bage\s+agora\b', r'\bcorra\b', r'\bprazo\b', r'\bamanhã\b',
        r'\bhoje\s+mesmo\b', r'\bagora\s+ou\s+nunca\b', r'\bfinal\s+de\s+semana\b'
    ]
    
    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    return 0


# Rule 11: Account Security Words Detection
def rule11(text: str) -> int:
    """
    Checks if a text contains account-related security words.
    Returns 1 if any account security word is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for account security words
        
    Returns:
        int: 1 if account security words are found, 0 otherwise
    """
    text_lower = text.lower()
    
    account_patterns = [
        r'\bconta[s]?\b', r'\bsenha[s]?\b', r'\blogin\b', r'\bverificar\b', r'\bsegurança\b',
        r'\batualizar\b', r'\bconfirmar\b', r'\bvalidar\b', r'\bautenticar\b', r'\bredefinir\b',
        r'\bsuspensa\b', r'\bbloqueada\b', r'\bdesativada\b', r'\breativar\b', r'\bcpf\b',
        r'\brg\b', r'\bdados\s+pessoais\b', r'\binformações\s+pessoais\b'
    ]
    
    for pattern in account_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    return 0


# Rule 12: Official Authority Words Detection
def rule12(text: str) -> int:
    """
    Checks if a text contains official-sounding authority words.
    Returns 1 if any official authority word is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for official authority words
        
    Returns:
        int: 1 if official authority words are found, 0 otherwise
    """
    text_lower = text.lower()
    
    official_patterns = [
        r'\baviso\b', r'\balerta[s]?\b', r'\badvertência[s]?\b', r'\bimportante\b', r'\boficial\b',
        r'\blegal\b', r'\bgoverno\b', r'\bbanco\b', r'\bimposto[s]?\b', r'\bindenização\b',
        r'\bautoridade\b', r'\bagência\b', r'\bdepartamento\b', r'\bpagamento[s]?\b',
        r'\breceita\s+federal\b', r'\bserasa\b', r'\bspc\b', r'\bcaixa\b', r'\bbrasília\b',
        r'\bministério\b', r'\btribunal\b', r'\bjustiça\b'
    ]
    
    for pattern in official_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    return 0


# Rule 13: Call to Action Words Detection
def rule13(text: str) -> int:
    """
    Checks if a text contains call-to-action words that prompt immediate response.
    Returns 1 if any call-to-action word is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for call-to-action words
        
    Returns:
        int: 1 if call-to-action words are found, 0 otherwise
    """
    text_lower = text.lower()
    
    action_patterns = [
        r'\bclicar\b', r'\bclique\b', r'\bseguir\b', r'\bligar\b', r'\bregistrar\b', r'\binscrever\b',
        r'\bse\s+inscrever\b', r'\baplicar\b', r'\bbaixar\b', r'\benviar\b', r'\bresponder\b',
        r'\bcompletar\b', r'\bvisitar\b', r'\bverificar\b', r'\blink\b', r'\bsite\b',
        r'\binformações\b', r'\bpreencher\b', r'\bcadastrar\b', r'\bconfirme\b'
    ]
    
    for pattern in action_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    return 0


# Rule 14: Brazilian Specific Scam Terms Detection
def rule14(text: str) -> int:
    """
    Checks if a text contains Brazilian-specific scam terms and institutions.
    Returns 1 if any Brazilian-specific scam term is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for Brazilian-specific scam terms
        
    Returns:
        int: 1 if Brazilian-specific scam terms are found, 0 otherwise
    """
    text_lower = text.lower()
    
    brazilian_patterns = [
        # Brazilian financial institutions
        r'\bbanco\s+do\s+brasil\b', r'\bcaixa\s+econômica\b', r'\bitaú\b', r'\bbradesco\b',
        r'\bsantander\b', r'\bnubank\b', r'\binter\b', r'\boriginal\b', r'\bbtg\b',
        
        # Brazilian government programs
        r'\bauxi[lí]io\s+emergencial\b', r'\bbolsa\s+família\b', r'\bauxi[lí]io\s+brasil\b',
        r'\bfgts\s+esquecido\b', r'\bpis\s+pasep\b', r'\bimposto\s+de\s+renda\b',
        r'\brestituição\b', r'\bcadastro\s+positivo\b',
        
        # Brazilian credit/financial terms
        r'\bcpf\s+irregular\b', r'\bnome\s+sujo\b', r'\bscore\b', r'\bnegativado\b',
        r'\blimpar\s+nome\b', r'\bempréstimo\s+aprovado\b', r'\bcartão\s+de\s+crédito\b',
        r'\bconsórcio\b', r'\bchave\s+pix\b', r'\btransfer[eê]ncia\s+pix\b',
        
        # Brazilian institutions
        r'\breceita\s+federal\b', r'\bbanco\s+central\b', r'\bdetran\b', r'\btse\b',
        r'\binss\b', r'\bprocon\b', r'\bgoverno\s+federal\b'
    ]
    
    for pattern in brazilian_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    return 0


# Rule 15: Pressure Tactics Detection
def rule15(text: str) -> int:
    """
    Checks if a text contains pressure tactics and exclusivity claims.
    Returns 1 if any pressure tactic is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for pressure tactics
        
    Returns:
        int: 1 if pressure tactics are found, 0 otherwise
    """
    text_lower = text.lower()
    
    pressure_patterns = [
        r'\bapenas\b', r'\bselecionado\b', r'\bescolhido\b', r'\bexclusivo\b', r'\bespecial\b',
        r'\bsorte\b', r'\bchance\b', r'\boportunidade\b', r'\brisco\b', r'\bproblema\b',
        r'\bagora\b', r'\bhoje\b', r'\búltimo\b', r'\búnica\s+vez\b', r'\bfinal\b',
        r'\bperdendo\b', r'\bperder\b', r'\boferta\s+limitada\b', r'\bparabéns\b',
        r'\bvocê\s+ganhou\b', r'\bloteria\b', r'\bsorteio\s+de\s+prêmios\b',
        r'\bnão\s+reivindicado\b', r'\boferta\s+única\b', r'\bnegócio\s+exclusivo\b'
    ]
    
    for pattern in pressure_patterns:
        if re.search(pattern, text_lower):
            return 1
    
    return 0


# Rule 16: Suspicious Word Combinations Detection
def rule16(text: str) -> int:
    """
    Checks if a text contains suspicious combinations of words that are more indicative
    of scam messages when found together.
    Returns 1 if any suspicious combination is found, 0 otherwise.
    
    Parameters:
        text (str): The input text to check for suspicious word combinations
        
    Returns:
        int: 1 if suspicious word combinations are found, 0 otherwise
    """
    text_lower = text.lower()
    
    # Look for combinations of suspicious elements
    combinations = [
        # Urgency + financial (Portuguese)
        r'\b(urgente|rápido|agora|hoje)\b.*\b(grátis|dinheiro|prêmio|ganhar)\b',
        r'\b(grátis|dinheiro|prêmio|ganhar)\b.*\b(urgente|rápido|agora|hoje)\b',
         
        # Action + account (Portuguese)
        r'\b(clicar|ligar|responder)\b.*\b(conta|senha|verificar|cpf)\b',
        r'\b(conta|senha|verificar|cpf)\b.*\b(clicar|ligar|responder)\b',
         
        # Financial + pressure (Portuguese)
        r'\b(dinheiro|grátis|ganhar|prêmio)\b.*\b(apenas|exclusivo|especial|chance)\b',
        r'\b(apenas|exclusivo|especial|chance)\b.*\b(dinheiro|grátis|ganhar|prêmio)\b',
        
        # Official + urgent (Portuguese)
        r'\b(banco|governo|receita|oficial)\b.*\b(urgente|imediato|agora)\b',
        r'\b(urgente|imediato|agora)\b.*\b(banco|governo|receita|oficial)\b',
        
        # Prize + action (Portuguese)
        r'\b(ganhou|prêmio|sorteio|parabéns)\b.*\b(clicar|ligar|responder|confirmar)\b',
        r'\b(clicar|ligar|responder|confirmar)\b.*\b(ganhou|prêmio|sorteio|parabéns)\b'
    ]
    
    for pattern in combinations:
        if re.search(pattern, text_lower):
            return 1
    
    return 0