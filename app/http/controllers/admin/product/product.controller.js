const Controller = require("../../controller");
const { StatusCodes: HttpStatus } = require("http-status-codes");
const mongoose = require("mongoose");
const {
  copyObject,
  deleteInvalidPropertyInObject,
} = require("../../../../../utils/functions");
const createHttpError = require("http-errors");
// const { CommentController } = require("../../comment/comment.controller");
const ObjectId = mongoose.Types.ObjectId;
const { HousetypesSchemaModel } = require("../../../../models/houseTypes");
const { UserModel } = require("../../../../models/user");
const { ProductModel } = require("../../../../models/product");
const {
  addProductSchema,
  changeCourseDiscountSchema,
} = require("../../../validators/admin/product.schema");

class ProductController extends Controller {
  async addNewProduct(req, res) {
    // const seller = req.user._id;
    await addProductSchema.validateAsync(req.body);
    const {
      title,
      description,
      imageLink,
      houseGroup,
      price,
      discount = 0,
      offPrice,
      typecars,
      rooms,
      parking,
      warHouse,
      WC,
      WCType,
      elevator,
      floor,
      collingSystem,
      heatingSystem,
      floorMaterial,
      city,
    } = req.body;

    const product = await ProductModel.create({
      title,
      description,
      imageLink,
      houseGroup,
      price,
      discount,
      offPrice,
      typecars,
      rooms,
      parking,
      warHouse,
      WC,
      WCType,
      elevator,
      floor,
      collingSystem,
      heatingSystem,
      floorMaterial,
      city,
    });
    if (!product?._id)
      throw createHttpError.InternalServerError("محصول ثبت نشد");
    return res.status(HttpStatus.CREATED).json({
      statusCode: HttpStatus.CREATED,
      data: {
        message: "محصول با موفقیت ایجاد شد",
        product,
      },
    });
  }
  async getListOfProducts(req, res) {
    let dbQuery = {};
    const user = req.user;
    const {
      search,
      houseGroup,
      sort,
      offPrice,
      rooms,
      parking,
      warHouse,
      WC,
      WCType,
      elevator,
      floor,
      collingSystem,
      heatingSystem,
      floorMaterial,
      city,
      page = 1,
      limit = 10,
    } = req.query;

    if (search) dbQuery["$text"] = { $search: search };

    if (houseGroup) {
      const houseGroups = houseGroup.split(",");
      const houseGroupIds = [];
      for (const item of houseGroups) {
        const { _id } = await HousetypesSchemaModel.findOne({ title: item });
        houseGroupIds.push(_id);
      }
      dbQuery["houseGroup"] = { $in: houseGroupIds };
    }

    const combinedIds = [];
    if (
      rooms ||
      parking ||
      warHouse ||
      WC ||
      WCType ||
      elevator ||
      floor ||
      collingSystem ||
      heatingSystem ||
      floorMaterial ||
      city
    ) {
      const queryConditions = [];
      if (rooms) queryConditions.push({ rooms: { $in: rooms } });
      if (parking) queryConditions.push({ parking: { $in: parking } });
      if (warHouse) queryConditions.push({ warHouse: { $in: warHouse } });
      if (WC) queryConditions.push({ WC: { $in: WC } });
      if (WCType) queryConditions.push({ WCType: { $in: WCType } });
      if (elevator) queryConditions.push({ elevator: { $in: elevator } });
      if (floor) queryConditions.push({ floor: { $in: floor } });
      if (collingSystem)
        queryConditions.push({ collingSystem: { $in: collingSystem } });
      if (heatingSystem)
        queryConditions.push({ heatingSystem: { $in: heatingSystem } });
      if (floorMaterial)
        queryConditions.push({ floorMaterial: { $in: floorMaterial } });
      if (city) queryConditions.push({ city: { $in: city } });

      const combinedProducts = await ProductModel.find({
        $or: queryConditions,
      });
      combinedIds.push(...combinedProducts.map((product) => product._id));
      dbQuery["_id"] = { $in: combinedIds };
    }

    if (offPrice) {
      dbQuery["offPrice"] = { $lte: offPrice };
    }

    const sortQuery = {};
    if (!sort) sortQuery["createdAt"] = 1;
    if (sort) {
      if (sort === "latest") sortQuery["createdAt"] = -1;
      if (sort === "earliest") sortQuery["createdAt"] = 1;
      if (sort === "popular") sortQuery["likes"] = -1;
    }

    // Calculate skip and limit
    const skip = (page - 1) * limit;

    // Fetch products with pagination
    const products = await ProductModel.find(dbQuery, { reviews: 0 })
      .populate([{ path: "houseGroup", select: { title: 1, englishTitle: 1 } }])
      .sort(sortQuery)
      .skip(skip)
      .limit(parseInt(limit));

    const transformedProducts = copyObject(products);

    const newProducts = transformedProducts.map((product) => {
      product.likesCount = product.likes.length;
      product.isLiked = false;
      if (!user) {
        product.isLiked = false;
        delete product.likes;
        return product;
      }
      if (product.likes.includes(user._id.toString())) {
        product.isLiked = true;
      }
      delete product.likes;
      return product;
    });

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        products: newProducts,
        page: parseInt(page),
        limit: parseInt(limit),
        total: await ProductModel.countDocuments(dbQuery), // Add total count of documents
      },
    });
  }

  async getProductById(req, res) {
    const { id: productId } = req.params;
    await this.findProductById(productId);
    const product = await ProductModel.findById(productId).populate([
      {
        path: "houseGroup",
        model: "houseGroup",
        select: {
          title: 1,
          icon: 1,
        },
      },
    ]);

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        product,
      },
    });
  }



  async changeProductDiscountStatus(req, res) {
    const { id } = req.params;
    await this.findProductById(id);
    await changeCourseDiscountSchema.validateAsync(req.body);
    const { discount, offPrice } = req.body;
    const result = await ProductModel.updateOne(
      { _id: id },
      { $set: { discount, offPrice } }
    );
    if (result.modifiedCount > 0) {
      return res.status(HttpStatus.OK).json({
        statusCode: HttpStatus.OK,
        data: {
          message: "وضعیت تخفیف محصول فعال شد",
        },
      });
    }
    throw createHttpError.BadRequest("تغییر انجام نشد مجددا تلاش کنید");
  }
  async removeProduct(req, res) {
    const { id } = req.params;
    await this.findProductById(id);
    const deleteResult = await ProductModel.deleteOne({ _id: id });
    if (deleteResult.deletedCount == 0)
      throw createError.InternalServerError("حدف محصول انجام نشد");
    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: "حذف محصول با موفقیت انجام شد",
      },
    });
  }
  async updateProduct(req, res) {
    const { id } = req.params;
    await this.findProductById(id);
    const data = copyObject(req.body);
    let blackListFields = ["bookmarks", "likes", "reviews"];
    deleteInvalidPropertyInObject(data, blackListFields);
    const updateProductResult = await ProductModel.updateOne(
      { _id: id },
      {
        $set: data,
      }
    );
    if (!updateProductResult.modifiedCount)
      throw new createHttpError.InternalServerError(
        "به روزرسانی محصول انجام نشد"
      );

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: "به روزرسانی محصول با موفقیت انجام شد",
      },
    });
  }
  async likeProduct(req, res) {
    const { id: productId } = req.params;
    const user = req.user;
    const product = await this.findProductById(productId);
    const likedProduct = await ProductModel.findOne({
      _id: productId,
      likes: user._id,
    });
    const updateProductQuery = likedProduct
      ? { $pull: { likes: user._id } }
      : { $push: { likes: user._id } };

    const updateUserQuery = likedProduct
      ? { $pull: { likedProducts: product._id } }
      : { $push: { likedProducts: product._id } };

    const productUpdate = await ProductModel.updateOne(
      { _id: productId },
      updateProductQuery
    );
    const userUpdate = await UserModel.updateOne(
      { _id: user._id },
      updateUserQuery
    );

    if (productUpdate.modifiedCount === 0 || userUpdate.modifiedCount === 0)
      throw createHttpError.BadRequest("عملیات ناموفق بود.");

    let message;
    if (!likedProduct) {
      message = "مرسی بابت لایک تون";
    } else message = "لایک شما برداشته شد";

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message,
      },
    });
  }

  async findProductById(id) {
    if (!mongoose.isValidObjectId(id))
      throw createHttpError.BadRequest("شناسه محصول ارسال شده صحیح نمیباشد");
    const product = await ProductModel.findById(id);
    if (!product) throw createHttpError.NotFound("محصولی یافت نشد.");
    return product;
  }
}

module.exports = {
  ProductController: new ProductController(),
};
