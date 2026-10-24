import express, { type Request, type Response } from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'UP', message: 'DevSecOps Service Running' });
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
