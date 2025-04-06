# SEMINARI JWT

## Descripció
Una API bàsica desenvolupada en Node.js amb TypeScript, utilitzant Express i Mongoose per a la gestió de dades en MongoDB. A més, s'inclou documentació amb Swagger.

A partir del projecte d'exemple del seminari de l'API muntarem un exemple d'ús de JWT amb autentificació.

## Requisits previs
Abans d'executar el projecte, assegura't de tenir instal·lat:
- [Node.js](https://nodejs.org/)
- [MongoDB](https://www.mongodb.com/)

## Instal·lació
Clona el repositori i executa la següent comanda per instal·lar les dependències:

```sh
npm install
```

## Configuració
Crea un fitxer `.env` a la arrel del projecte i defineix les següents variables d'entorn//canviar les strings directament en el codi a les línies 16 (Port) i 69 (uri mongo) :
```env
MONGO_URI=mongodb://localhost:27017/la_teva_base_de_dades
PORT=9000
```

## Execució
Per iniciar l'API (tsc + cd ./build + node server.js):

```sh
npm start
```

## Documentació
Swagger està disponible a:
```
http://localhost:9000/api-docs
```

## Dependències Principals
- `dotenv`: Gestió de variables d'entorn.
- `mongodb` i `mongoose`: Base de dades MongoDB.
- `swagger-jsdoc` i `swagger-ui-express`: Generació de documentació.
- `express`: Framework per a l'API.

## Dependències de Desenvolupament
- `typescript`: Suport per a TypeScript.
- `@types/*`: Definicions de tipus per a biblioteques utilitzades.

## Dependències JWT
-Comanda per instalar dependències: 'npm i bcryptjs jsonwebtoken'.
- '@types/bcryptjs' -> Tipats
- '@types/jsonwebtoken' -> Tipats

## Configuració d'OAuth 2.0 amb Google

Crear les credencials d'OAuth 2.0

1.- Accedeix a la Google Cloud Console.

2.- Selecciona o crea un nou projecte.

3.- A la barra lateral, ves a APIs & Services > Credentials.

4.- Fes clic a Create Credentials i selecciona OAuth 2.0 Client ID.

5.- Si encara no has configurat una pantalla de consentiment d'OAuth, hauràs de fer-ho:

    --> Omple els camps requerits, com el nom de l'aplicació i el correu electrònic de suport.

6.- Afegeix els dominis autoritzats si és necessari.

7.- Desa la configuració.

8.- Selecciona Application type com Web application ( ja que ho fem amb angular) .

9.- Defineix un nom per a les credencials.

10.- Afegeix l'URL de redirecció a la secció Authorized redirect URIs:
```
http://localhost:9000/api/auth/google/callback per a desenvolupament local.
```
11.- Desa la configuració i copia el Client ID i el Client Secret.

12.- Configuració de les variables d'entorn

13.- Al servidor backend, afegeix les variables d'entorn necessàries en un fitxer .env:
```
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_OAUTH_REDIRECT_URL=http://localhost:9000/api/auth/google/callback
```
14.- Assegurar que aquestes variables estiguin carregades abans d'iniciar el servidor, utilitzar per defecte npm start per fer RUN en el projecte (ruta per defecte per agafar les variables d'entorn integrada).


## Referències

[1] https://dev.to/jeanvittory/jwt-refresh-tokens-2g3d
[2] https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/
[3] companys de classe per resoldre lo de les rutes