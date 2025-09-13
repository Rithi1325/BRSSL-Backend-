import mongoose from "mongoose";

const backupLogSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: true,
      enum: ["export", "import"],
    },
    dataType: {
      type: String,
      required: true,
      enum: [
        "customers",
        "loans",
        "transactions",
        "vouchers",
        "reports",
        "employees",
        "jewels",
      ],
    },
    filename: {
      type: String,
      required: true,
    },
    recordCount: {
      type: Number,
      default: 0,
    },
    status: {
      type: String,
      enum: ["pending", "success", "failed"],
      default: "pending",
    },
    errorMessage: String,
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    metadata: {
      imported: { type: Number, default: 0 },
      updated: { type: Number, default: 0 },
      errors: { type: Array, default: [] },
      fileSize: Number,
      originalName: String,
    },
  },
  {
    timestamps: true,
  }
);

// ✅ Only define indexes once
backupLogSchema.index({ dataType: 1, type: 1, createdAt: -1 });
backupLogSchema.index({ userId: 1, createdAt: -1 });

const BackupLog = mongoose.model("BackupLog", backupLogSchema, "backuplogs");

export default BackupLog;
