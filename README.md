# WHOIS Dump - An OSINT Tool
Essa é uma ferramenta bem simples que visa realizar uma busca por um domínio ou IP em um servidor WhoIS e investigar um determinado alvo a partir das informações retornadas.  
Sua utilidade está em montar um perfil a ser utilizado um trabalho de Threat Intelligence para determinar se as informações expostas no banco de dados do WhoIS não são muito importantes para permanecerem abertas ao público.

## Objetivos
Atualmente os objetivos iniciais são simples:
- Realizar uma busca por qualquer domínio (.COM, .ORG, .NET e .BR) ou IP no WhoIS e retornar o JSON.
- Salvar esses dados e realizar buscas específicas a partir dos dados retornados.

## Hoje
O projeto hoje apenas realiza uma busca por um domínio .BR no WhoIS e retorna os dados em JSON.

