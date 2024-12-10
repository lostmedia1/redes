-- Crear la base de datos
CREATE DATABASE registro_mensajes;

-- Seleccionar la basede datos
\c registro_mensajes;

-- Crear la tabla si no existe
CREATE TABLE mensajes (
    id SERIAL PRIMARY KEY,
    protocolo VARCHAR(10),
    data TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
