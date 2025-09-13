// controllers/jewelRateController.js
import JewelRate from "../models/jewelRate.js";

// @desc    Get all jewel rates, sorted by latest date
// @route   GET /api/jewel-rates
// @access  Private
export const getJewelRates = async (req, res) => {
  try {
    const jewelRates = await JewelRate.find().sort({ date: -1 });
    res.json(jewelRates);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server Error" });
  }
};

// @desc    Get latest jewel rate by metal type
// @route   GET /api/jewel-rates/:metalType
// @access  Private
export const getJewelRateByType = async (req, res) => {
  try {
    const jewelRate = await JewelRate.findOne({ metalType: req.params.metalType })
                                     .sort({ date: -1 });
    if (!jewelRate) {
      return res.status(404).json({ message: "Jewel rate not found" });
    }
    res.json(jewelRate);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server Error" });
  }
};

// @desc    Create or update a jewel rate
// @route   POST /api/jewel-rates
// @access  Private (Admin)
export const createOrUpdateJewelRate = async (req, res) => {
  try {
    const { metalType, rate, date } = req.body;
    if (!metalType || !rate) {
      return res.status(400).json({ message: "Metal type and rate are required" });
    }

    const updatedRate = await JewelRate.findOneAndUpdate(
      { metalType },
      { rate, date: date || Date.now() },
      { new: true, upsert: true } // creates if not exists
    );

    res.status(200).json(updatedRate);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server Error" });
  }
};
