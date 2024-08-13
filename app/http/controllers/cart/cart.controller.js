const createHttpError = require("http-errors");
const { ProductModel } = require("../../../models/product");
const Controller = require("../controller");
const { StatusCodes: HttpStatus } = require("http-status-codes");
const {
  copyObject,
  getUserCartDetail,
} = require("../../../../utils/functions");
const { UserModel } = require("../../../models/user");
const { CouponModel } = require("../../../models/coupon");

class CartController extends Controller {
  async addToCart(req, res) {
    const userId = req.user;
    const { productId } = req.body;
    const addedProduct = await this.checkExistProduct(productId);
    const product = await this.findProductInCart(userId, productId);
    const existProduct = await this.findProductInCart(userId, productId);

    if (existProduct) {
      throw createHttpError.InternalServerError("It exists in your Cart");
    }
    if (product) {
      const addToCartResult = await UserModel.updateOne(
        {
          _id: userId,
          "cart.products.productId": productId,
        },
        {
          $inc: {
            "cart.products.$.quantity": 1,
          },
        }
      );
      if (addToCartResult.modifiedCount == 0)
        throw createHttpError.InternalServerError(
          "Product was not added to cart"
        );
    } else {
      const addToCartResult = await UserModel.updateOne(
        {
          _id: userId,
        },
        {
          $push: {
            "cart.products": {
              productId,
              quantity: 1,
            },
          },
        }
      );
      if (addToCartResult.modifiedCount == 0)
        throw createHttpError.InternalServerError(
          "Product was not added to cart"
        );
    }

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: `Added to cart: ${addedProduct.title}`,
      },
    });
  }

  async removeFromCart(req, res) {
    const userId = req.user._id;
    const { productId } = req.body;
    const removedProduct = await this.checkExistProduct(productId);
    const product = await this.findProductInCart(userId, productId);
    if (!product)
      throw createHttpError.BadRequest(
        `${removedProduct.title} is not in your cart`
      );
    let message;
    if (product.quantity > 1) {
      const decreaseCart = await UserModel.updateOne(
        {
          _id: userId,
          "cart.products.productId": productId,
        },
        {
          $inc: {
            "cart.products.$.quantity": -1,
          },
        }
      );
      if (decreaseCart.modifiedCount == 0)
        throw createHttpError.InternalServerError(
          "Product was not reduced from cart"
        );

      message = "One quantity of the product was removed from the cart";
    } else {
      const newCart = await UserModel.findOneAndUpdate(
        {
          _id: userId,
          "cart.products.productId": productId,
        },
        {
          $pull: {
            "cart.products": { productId },
          },
        },
        { new: true }
      );
      if (newCart.modifiedCount == 0)
        throw createHttpError.InternalServerError(
          "Product was not removed from cart"
        );

      message = "Product was removed from the cart";

      if (newCart.cart.products.length === 0)
        await UserModel.updateOne(
          { _id: userId },
          {
            $unset: { "cart.coupon": 1 },
          }
        );
    }

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: `${removedProduct.title} ${message}`,
      },
    });
  }
  async deleteFromCart(req, res) {
    const userId = req.user._id;
    const { productId } = req.body;
    const removedProduct = await this.checkExistProduct(productId);
    const product = await this.findProductInCart(userId, productId);

    if (!product) {
      throw createHttpError.BadRequest(
        `${removedProduct.title} is not in your cart`
      );
    }

    const newCart = await UserModel.findOneAndUpdate(
      { _id: userId, "cart.products.productId": productId },
      { $pull: { "cart.products": { productId } } },
      { new: true }
    );

    if (newCart.modifiedCount == 0) {
      throw createHttpError.InternalServerError(
        "Product was not removed from cart"
      );
    }

    const message = "Product was removed from the cart";

    if (newCart.cart.products.length === 0) {
      await UserModel.updateOne(
        { _id: userId },
        { $unset: { "cart.coupon": 1 } }
      );
    }

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: `${removedProduct.title} ${message}`,
      },
    });
  }
  async addCouponToCart(req, res) {
    const { couponCode } = req.body;
    const user = req.user;
    const coupon = await CouponModel.findOne({ code: couponCode });
    if (!coupon)
      throw createHttpError.BadRequest(
        "The entered coupon code does not exist"
      );
    if (coupon.usageCount >= coupon.usageLimit)
      throw createHttpError.BadRequest(
        "Coupon code usage limit has been reached"
      );
    if (
      coupon?.expireDate &&
      new Date(coupon.expireDate).getTime() < Date.now()
    )
      throw createHttpError.BadRequest("Coupon code has expired");
    if (!coupon.isActive)
      throw createHttpError.BadRequest("Coupon code is not active");
    const productIdsInCart = user.cart.products.map((p) =>
      p.productId.valueOf()
    );
    const isCouponIncludeCartItems = coupon.productIds.some((pId) =>
      productIdsInCart.includes(pId.valueOf())
    );
    if (!isCouponIncludeCartItems)
      throw createHttpError.BadRequest(
        "Coupon code does not apply to any of the products in your cart"
      );
    const addCouponToCart = await UserModel.updateOne(
      { _id: user._id },
      {
        $set: { "cart.coupon": coupon._id },
      }
    );
    if (addCouponToCart.modifiedCount == 0)
      throw new createHttpError.InternalServerError(
        "Coupon code was not applied"
      );

    const userCartDetail = (await getUserCartDetail(user._id))?.[0];
    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: "Coupon code was successfully applied",
        cart: userCartDetail,
      },
    });
  }
  async removeCouponFromCart(req, res) {
    const userId = req.user._id;

    const removeCouponFromCart = await UserModel.updateOne(
      { _id: userId },
      {
        $unset: { "cart.coupon": 1 },
      }
    );
    if (removeCouponFromCart.modifiedCount == 0)
      throw createHttpError.InternalServerError("Coupon code was not removed");
    const userCartDetail = (await getUserCartDetail(userId))?.[0];
    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: "Coupon code was removed",
        cart: userCartDetail,
      },
    });
  }
  async checkExistProduct(id) {
    const product = await ProductModel.findById(id);
    if (!product)
      throw createHttpError.NotFound(
        "Product with these specifications was not found"
      );
    return product;
  }
  async findProductInCart(userId, productId) {
    const findResult = await UserModel.findOne(
      { _id: userId, "cart.products.productId": productId },
      { "cart.products.$": 1 }
    );
    const userDetail = copyObject(findResult);
    return userDetail?.cart?.products?.[0];
  }
}

module.exports = {
  CartController: new CartController(),
};
