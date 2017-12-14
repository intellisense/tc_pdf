from tc_core import Extension, Extensions
from tc_pdf.handlers.pdf import PDFHandler

extension = Extension('tc_pdf')

# Register the route
extension.add_handler(PDFHandler.regex(), PDFHandler)

Extensions.register(extension)
