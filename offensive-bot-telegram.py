import os
from re import U
from time import sleep
from telegram import Update
from telegram.ext import Updater,CommandHandler,CallbackContext
from uuid import uuid4
from souzo_scrap import get_cve
from souzo_scrap import get_cwe
from zapv2 import ZAPv2
from random import randrange
import socket

telegramKey = "<YOUR TELEGRAM KEY>"

def transforma(texto : str,numero : int= 4000):
    chunks = [texto[i:i+numero] for i in range(0, len(texto), numero)]
    return chunks
def help(update: Update, context: CallbackContext):
    print("mensagem de " + str(update.message.chat.id))
    res = """BOT DE AJUDA PARA O RED TEAM
    --projects [ não implementado ]
    /add_project <nome do projeto> <cliente> <pentester> <data_final>
    /remove_project <nome do projeto>
    /list_project
    
    --commands
    /exec <comando> -> Executa um comando no nosso c2server
    /leaks_mail <domain> -> procura emails vazados de um dominio
    /help -> Mostra as opções do bot
    /subdomains <domain> 
    /cve <id> -> trás informação sobre uma cve
Funções que vão ser implementadas:
    /malware <windows | linux> -> gera um malware furtivo para linux ou windows.
    /server <command> -> Executa comandos no servidor de botnet criado por @Souzomain
    /exec -> Implementação do shell interativo
    /payload <type> <host> <port>
        windows
        linux
        jsp
        aspx
        asp
        C
        ruby
        python
        php
        xml
    -> Geração de payload OBS: PRECISO DE AJUDA NESSE GERADOR DE PAYLOAD

    /set_pentest <nome do pentester> <cliente> <data de termino> -> coloca um pentest para um cliente
    /get_pentest <cliente | all> -> trás todos os pentest pendentes
    /attack <website> -> estou pensando em implementar o burp e o netsparker para realizar um scan generico de falhas
    /recon <dominio> -> reconhecimento automatico de dominio
"""
    res = """
01010011 00101110 01001111 
00101110 01010011 00100000 
01000010 01001111 01010100

/exec <command>
/payload [break]
/attack <url> [--attack] [--wappalyzer]
/help
/cve <id>
/cwe <id>
/subdomains <domain>
/leaks_mail <domain>
/java_desser <type> <command>
/server <porta>
"""
    for i in transforma(res):
        update.message.reply_text(i)
def leaks_mail(update: Update, context: CallbackContext):
    print("mensagem de " + str(update.message.chat.id))
    try:
        mails = []
        with os.popen(f"karma search '{context.args[0]}' --domain") as f:
            for i in f.readlines():
                mails.append(i)
        for i in transforma(" ".join(mails)):
            update.message.reply_text(i)
            sleep(2)
    except Exception as ex:
        update.message.reply_text("Erro interno.")
        print(str(ex))
def payload(update: Update, context: CallbackContext):
    print("mensagem de " + str(update.message.chat.id))
    try:
        a = context.args[0]
        res = ""
        if "windows" in a:
            res = "powershell -bypass"
        if len(res) > 0:
            for i in transforma(res):
                update.message.reply_text(i)
                sleep(1)
        else:
            update.message.reply_text("Ocorreu um erro durante a geração do payload")
    except Exception as ex:
        print(str(ex))
        update.message.reply_text("Erro interno")
def shell_execute(update: Update, context: CallbackContext):
    idok = [""] #coloque o id do chat que está habilitado pra executar comandos nessa máquina
    if str(update.message.chat.id) not in idok:
        update.message.reply_text("Voce não tem permissão\nFale com @Souzomain")
        return
    try:
        print("mensagem de " + str(update.message.chat.id))
        print(" ".join(context.args))
        response = []
        i = 0
        if context.args[0] == "cd":
            os.chdir(context.args[1:])
            return
        with os.popen(" ".join(context.args), "r") as f:
            for x in f.readlines():
                if i > 50:
                    break
                i =i+1
                response.append(x)
        y = 0
        for i in transforma(" ".join(response)):
            if y > 10:
                break
            y = y+1
            update.message.reply_text(i)
            sleep(2)
    except Exception as ex:
        update.message.reply_text("Erro interno")
        print(str(ex))
def cvetelegram(update: Update, context: CallbackContext):
    try:
        print("mensagem de " + str(update.message.chat.id))
        res = transforma(get_cve(context.args[0]))
        for i in res:
            update.message.reply_text(i)
    except Exception as ex:
        update.message.reply_text("Erro interno")
        print(str(ex))

def cwetelegram(update: Update, context: CallbackContext):
    print("mensagem de " + str(update.message.chat.id))
    try:
        res = get_cwe(context.args[0])
        desc = str(res["Descricao"])
        cons = str(res["Consequencia"])
        update.message.reply_text(f"Descrição:\n{desc}\n\nConsequência:\n{cons}")
    except Exception as ex:
        print(str(ex))
        update.message.reply_text("Erro interno")
def get_subdomains(update: Update, context: CallbackContext):
    print("mensagem de " + str(update.message.chat.id))
    if "/" in context.args[0] or ":" in context.args[0] or "/" in context.args[0]:
        update.message.reply_text("coloque um domínio válido")
    try:
        results = []
        with os.popen(f"subfinder -d {context.args[0]} -silent ", "r") as f:
            #|httpx -silent -no-color -status-code -ip -follow-redirects -paths \"/api,/.git,/.env,/admin,/upload,/download\" -random-agent
            for i in f.readlines():
                results.append(i)
        for i in transforma(" ".join(results)):
            update.message.reply_text(i)
            sleep(1)
    except Exception as ex:
        update.message.reply_text("Erro interno.")
        print(str(ex))
def portopen(host,port):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as f:
            f.settimeout(5)
            r = f.connect_ex((host,port))
            if r == 0:
                return True
            else:
                return False
    except:
        return False
def get_urls(update: Update, context: CallbackContext):
    print("mensagem de " + str(update.message.chat.id) + " get urls")
    target = context.args[0]
    attck = False
    wpok = False
    sss = False
    if not "/" in target or not ":" in target:
        update.message.reply_text("coloque uma url válida")
        return
    if "--attack" in context.args:
        attck = True        
    if "--wappalyzer" in context.args:
        wpok = True
    ppp = randrange(2,65534)
    while(portopen("127.0.0.1",ppp)):
        ppp = randrange(2,65534)
    os.system(f"/opt/zaproxy/zap.sh -daemon -port {ppp} -config api.key='apikey' 2>&1 1>/dev/null &")
    sleep(10)
    zap = ZAPv2(proxies={"http":f"http://127.0.0.1:{ppp}","https":f"https://127.0.0.1:{ppp}"},apikey="apikey")
    sid = zap.spider.scan(url=target)
    try:
        while(int(zap.spider.status(sid)) < 100):
            pass
        while int(zap.pscan.records_to_scan) > 0:
            pass
    except Exception as ex:
        update.message.reply_text(f"Erro ao escanear {str(ex)}")
    else:
        if attck:
            sid = zap.ascan.scan(target)
            while int(zap.ascan.status(sid)) < 100:
                pass
        try: 
            file = f"/tmp/SPIDER.{uuid4()}" 
            with open(file,"w") as f:
                for i in zap.spider.results(sid):
                    f.write(i.strip()+"\n")
            with open(file,"rb") as f:
                update.message.reply_document(document=f)
            os.remove(file)
            file = f"/tmp/WAPPALYZER.{uuid4()}"
            num = 0
            if wpok:
                with open(file,"w") as f:
                    json = zap.wappalyzer.list_all
                    if json in "no_implementor":
                        update.message.reply_text("wappalyzer não implementado")
                        print(json)
                    else:
                        print(json)
                        for results in json:
                            for k,v in results.items():
                                for i in v:
                                    num +=1
                                    f.write(f"site: {k} | {i['name'] if i['name'] != '' else 'None'} | {i['version'] if i['version'] != '' else 'None'}\n")
                if num > 0:
                    with open(file,"rb") as f:
                        update.message.reply_document(document=f)
                os.remove(file)
            num = 0
            file = f"/tmp/SCAN.{uuid4()}"
            with open(file,"w") as f:
                for i in zap.core.alerts():
                    num+=1    
                    f.write(f"{num} | {i['url']} | {i['name']} | CWE: {i['cweid']} | {i['risk']} | {i['confidence']}\n")
            if num!=0:
                with open(file,"rb") as f:
                    update.message.reply_document(document=f)
            os.remove(file)
            print(zap.core.alerts())
        except Exception as ex:
            update.message.reply_text(f"Ocorreu um erro: {str(ex)}")
    finally:
        zap.core.shutdown()
def server(update: Update, context: CallbackContext):
    try:
        porta = context.args[0]
        if porta.isdigit() and porta > 0 and porta < 65000:
            os.system(f"/root/telegram/server $(curl echoip.ir) {porta}")
        else:
            update.message.reply_text("Nao foi possivel iniciar o servidor")    
    except Exception as ex:
        update.message.reply_text(f"Nao foi possivel iniciar o servidor {str(ex)}")
updater = Updater(telegramKey)
os.chdir("/root")
updater.dispatcher.add_handler(CommandHandler("exec",shell_execute))
#updater.dispatcher.add_handler(CommandHandler("payload",payload))
updater.dispatcher.add_handler(CommandHandler("help",help))
updater.dispatcher.add_handler(CommandHandler("leaks_mail",leaks_mail))
updater.dispatcher.add_handler(CommandHandler("cve",cvetelegram))
updater.dispatcher.add_handler(CommandHandler("cwe",cwetelegram))
updater.dispatcher.add_handler(CommandHandler("subdomains",get_subdomains))
updater.dispatcher.add_handler(CommandHandler("attack",get_urls))
#updater.dispatcher.add_handler(CommandHandler("server",server))

updater.start_polling()
updater.idle()

