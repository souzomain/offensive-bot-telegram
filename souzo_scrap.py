import requests

def getext(texto : str,tag1 : str, tag2 : str ):
    texto = texto.split(tag1)[1]
    return texto.split(tag2)[0]

def get_cve(id):
    h = {
        "Host":"cve.mitre.org",
        "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
        "Accept":"*/*"
    }
    a = requests.get(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{id}",headers=h)
    return getext(a.text,"<td colspan=\"2\">","</td>").strip()
def get_cwe(id):
    try:
        h = {
            "Host": "cwe.mitre.org",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        a = requests.get(f"https://cwe.mitre.org/data/definitions/{id}.html",headers=h).text
        
        return {"Descricao":getext(a,"<div class=\"indent\">","</div>").strip(), "Consequencia": getext(a,"<div class=\"indent\"><p>","</p>").strip()}
        
    except Exception as ex:
        return "erro"