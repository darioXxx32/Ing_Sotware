const express = require("express")

const app = express()
app.use(express.json())

// ruta principal
app.get("/", (req, res) => {
  res.send("Servidor funcionando")
})

// iniciar servidor
app.listen(3000, () => {
  console.log("Servidor corriendo en http://localhost:3000")
})