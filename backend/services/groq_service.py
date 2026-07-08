import os
from groq import Groq
from core.config import settings

# Initialize the Groq client. It will automatically pick up GROQ_API_KEY from environment variables if set,
# or we can pass it explicitly.
client = Groq(api_key=settings.GROQ_API_KEY)

AVAILABLE_MODELS = {
    "llama-3.3-70b-versatile": "Llama 3.3 70B (Legacy)",
    "openai/gpt-oss-120b": "GPT-OSS 120B (Recommended)",
    "openai/gpt-oss-20b": "GPT-OSS 20B (Fastest)",
    "qwen/qwen3.6-27b": "Qwen 3.6 27B"
}

async def chat_with_ai(message: str, history: list = [], model: str = "openai/gpt-oss-120b"):
    try:
        SYSTEM_PROMPT = """You are ThreatMap AI. 
Format your responses using proper Markdown:
- Use ```language code blocks for ANY code, scripts, or commands
- Use proper Markdown tables (| col | col |) for ANY 
  tabular data, comparisons, schedules, or lists with 
  multiple attributes per item
- Use numbered lists for sequential steps
- Use bullet points for unordered items
- Use **bold** only for key terms, not whole sentences
- Never describe a table or code in plain prose when 
  the user is asking for one - always use proper 
  Markdown syntax
"""
        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            *history,
            {"role": "user", "content": message}
        ]
        
        response = client.chat.completions.create(
            messages=messages,
            model=model,
            temperature=0.7,
            max_tokens=1024
        )
        
        return response.choices[0].message.content
    except Exception as e:
        return f"Error with {model}: {str(e)}"

async def chat_with_image(message: str, base64_image: str):
    try:
        # Use exact model requested by user
        model = "meta-llama/llama-4-scout-17b-16e-instruct"
        
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": message},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}}
                ]
            }
        ]
        
        response = client.chat.completions.create(
            messages=messages,
            model=model,
            temperature=0.7,
            max_tokens=1024
        )
        
        return response.choices[0].message.content
    except Exception as e:
        return f"Error with vision model {model}: {str(e)}"
