import requests as re

r = re.post('http://127.0.0.1:5000/register', {
    'name': 'parsa'
})
print(r.text)
