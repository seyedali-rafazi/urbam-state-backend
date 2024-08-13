const Joi = require("joi");
const createHttpError = require("http-errors");

const addCouponSchema = Joi.object({
  code: Joi.string()
    .required()
    .min(5)
    .max(30)
    .error(createHttpError.BadRequest("Invalid discount code")),
  type: Joi.string()
    .required()
    .valid("fixedProduct", "percent")
    .error(createHttpError.BadRequest("Please enter a valid discount type")),
  amount: Joi.number()
    .required()
    .error(createHttpError.BadRequest("Please enter a valid discount amount")),
  expireDate: Joi.date()
    .allow()
    .error(createHttpError.BadRequest("Please enter a valid expiration date")),
  usageLimit: Joi.number()
    .required()
    .error(createHttpError.BadRequest("Please enter a valid usage limit")),
  productIds: Joi.array().error(
    createHttpError.BadRequest("Invalid product ID")
  ),
});

module.exports = {
  addCouponSchema,
};
