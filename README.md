# Cookie Stealer

Prueba de concepto de un Cookie Stealer en Python. Implementado para Google Chrome tanto para Windows como para Linux (
Ubuntu).

## Creacion de entorno virtual

En ambos sistemas operativos

```bash
python3 -m venv .venv
```

Luego activar el entorno virtual

### Windows

```bash
C:\> <venv>\Scripts\activate.bat
```

### Ubuntu

```bash
source <venv>/bin/activate"
```

Donde `<venv>` es el nombre del directorio donde se creó el entorno virtual. Por ejemplo, si el directorio se encuentra
en `/home/user/cookie-stealer`, entonces el comando seria `source /home/user/cookie-stealer/.venv/bin/activate`

## Ejecucion en Windows

Parados en la raiz del proyecto.

### Instalar requerimientos

```bash
pip3 install -r requirements.txt
```

### Correr server

```bash
python3 -m uvicorn server.main:app
```

### Recolectar cookies y enviarlas al servidor

```bash
python3 .\stealer.py
```

## Ejecución en Ubuntu

### Instalar requerimientos en Ubuntu

```bash
pip3 install -r requirements-ubuntu.txt
```

### Recolectar cookies e imprimirlas por pantalla

```bash
python3 ./stealer-ubuntu.py
```
