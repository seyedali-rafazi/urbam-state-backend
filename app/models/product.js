const mongoose = require("mongoose");
const ObjectId = mongoose.Schema.Types.ObjectId;

const ProductSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String, required: true },
    houseGroup: { type: ObjectId, ref: "houseGroup", required: true },
    imageLink: { type: String, required: true },
    price: { type: Number, required: true },
    offPrice: { type: Number, required: true },
    discount: { type: Number, default: 0 },
    rating: { type: Number, required: true, default: 0 },
    numReviews: { type: Number, required: true, default: 0 },
    likes: { type: [ObjectId], ref: "User", default: [] },
    rooms: { type: Number, required: true },
    parking: { type: Number, required: true },
    warHouse: { type: Number, required: true },
    WC: { type: Number, required: true },
    WCType: { type: String, required: true },
    elevator: { type: Number, required: true },
    floor: { type: Number, required: true },
    collingSystem: { type: String, required: true },
    heatingSystem: { type: String, required: true },
    floorMaterial: { type: String, required: true },
    city: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

// Create a text index on the 'title' and 'description' fields
ProductSchema.index({ title: "text", description: "text" });

module.exports = {
  ProductModel: mongoose.model("Product", ProductSchema),
};
