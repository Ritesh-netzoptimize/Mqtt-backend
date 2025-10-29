import express from 'express';
import cors from 'cors';
import { attachUser } from './controllers/AuthController.js';
import authRoutes from './routes/authRoutes.js';
import morgan from 'morgan';
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// app.use(attachUser);

app.get('/', (req, res) => {
    res.send('API is running');
});

app.use(`/api/v1/auth`, authRoutes);

export default app;
