# Telegram Bot RedTeam
---

<p>
  Um bot para telegram com foco em redteam.
  Para configurar basta colocar a key do bot que você criou em telegramKey na linha 16
  O Bot conta com várias funções para automatizar pentestes, incluindo a utilização da api do Zaproxy
</p>

<details open>
  <summary>attack</summary>
<p>
  A opção de attack do bot conta com a ajuda do zaproxy para realizar um um scan ao domínio utilizando técnicas passivas e ativas para descoberta de vulnerabilidades.
  Como parâmetro você pode passar --wappalyzer para pegar informações de banners do alvo. (Você tem que ter baixado o plugin do wappalyzer no zaproxy antes.)
  A opção --attack serve para realizar um ataque ativo no alvo, por exemplo um scan de sql injection, por padrão ele só faz scan passivo.
</p>
</details>
<details open>
  <summary>exec</summary>
<p>
  Executa um comando no servidor onde o bot ta hospedado.
</p>
</details>
<details open>
  <summary>cve & cwe</summary>
<p>
  Realiza um scrapping no website do mitre a procura do cwe/cve indicado. 
</p>
</details>
<details open>
  <summary>subdomains</summary>
<p>
  Realiza uma procura de subdominios no domínio específicado
</p>
</details>
<details open>
  <summary>leaks_mail</summary>
<p>
  Realiza uma busca de emails vazados na deep web.
</p>
</details>

# Considerações finais
---

<p>
  O projeto ainda está em desenvolvimento e várias funções ainda vão ser adicionadas, por exemplo um scan em rede interna.
  Não sei se ainda vou continuar a desenvolver o projeto e melhorar a estrutura dele, porém da para usar, editar e melhorar esta simples tool.
  Faça bom uso :)
</p>
