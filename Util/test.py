import PyPDF2

pdfFileObj = open('flat.pdf', 'rb')
pdfReader = PyPDF2.PdfFileReader(pdfFileObj)
#print(pdfReader.getDocumentInfo())
pageObj = pdfReader.getPage(0)
print(pageObj.extractText())
#print(pdfReader.getNamedDestinations())
