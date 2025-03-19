from django.core.exceptions import ValidationError

def validate_file_extension(value):
    valid_extensions = ['.zip', '.rar', '.7z']
    if not any(value.name.lower().endswith(ext) for ext in valid_extensions):
        raise ValidationError('Unsupported file extension')