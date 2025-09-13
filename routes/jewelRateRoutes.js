// routes/jewelRateRoutes.js
import express from "express";
import {
  getJewelRates,
  createOrUpdateJewelRate,
} from "../controllers/jewelRateController.js";

const router = express.Router();

router.get("/", getJewelRates);
router.post("/", createOrUpdateJewelRate);

export default router;
