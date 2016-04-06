# Tahin

Github: https://github.com/mtesseract/tahin

Tahin is a KISS-style password generator based on the
[password creation concept](http://www.foc.rub.de/people/spiegel_pass.html.en)
suggested by
e.g. Prof. Dr. [Eike Kiltz](http://www.foc.rub.de/people/kiltz.html).

The idea is that there exists a secure master password and a
service-specific ‘identifier’. These two strings get concatenated,
then you transform the concatenated string with a secure hashing
function and base64-encode the result.
