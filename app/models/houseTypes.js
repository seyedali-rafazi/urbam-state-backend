const mongoose = require("mongoose");

const HousetypesSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, unique: true },
    englishTitle: { type: String, required: true, unique: true },
    type: {
      type: String,
      enum: ["product", "comment", "post", "ticket", "housegroups"],
      default: "houseGroup",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

HousetypesSchema.index({ title: "text", englishTitle: "text" });

module.exports = {
  HousetypesSchemaModel: mongoose.model("houseGroup", HousetypesSchema),
};
