import { app, query, errorHandler } from "mu";

app.get("/status", function (req, res) {
  res.send({
    service: "vc-issuer-service",
    status: "ok",
  });
});

app.use(errorHandler);
