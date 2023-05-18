import json

from deep_translator import GoogleTranslator


class TextTranslation:
    def __init__(self):
        self.to_lang = "ru"

    def translate(self, text: str) -> str:
        if text == "None":
            return "None"
        translated_text = GoogleTranslator(source='auto', target=self.to_lang).translate(text=text[:5000])
        return translated_text