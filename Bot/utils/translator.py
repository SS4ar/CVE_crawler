from deep_translator import GoogleTranslator


class TextTranslation:
    def __init__(self):
        self.to_lang = "ru"

    def translate(self, text: str):
        translated_text = GoogleTranslator(source='auto', target=self.to_lang).translate(text=text)
        return translated_text