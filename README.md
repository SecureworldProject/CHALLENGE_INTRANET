# CHALLENGE_INTRANET

Este challenge tiene como objetivo distinguir la red a la que se está conectada de manera que genere resultados distintos si es la intranet de la empresa o no. Realiza accesos a urls concretas (definidas en los parámetros del challenge) y genera un stream binario de 0s y 1s en función de si la conexión a cada url fue completada o no.

ejemplo de configuracion
```json
{
	"FileName": "CHALLENGE_INTRANET.dll",
	"Description": "This challenge creates a key which is a stream of 0s and 1s that represent the accessibility to different urls.",
	"Props": {
	"validity_time": 3600,
	"refresh_time": 3000,
	"urls":
		[
			"helios.nsn-intra.net",
			"nokia.sharepoint.com",
			"wam.inside.nsn.com",
			"lawson.web.alcatel-lucent.com",
			"www.google.com",
			"www.yahoo.com",
			"www.google.es",
			"www.youtube.com"
		]
	},
	"Requirements": "none"
}

```
