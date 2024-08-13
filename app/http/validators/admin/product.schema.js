const createError = require("http-errors");
const Joi = require("joi");
const { MongoIDPattern } = require("../../../../utils/constants");

const addProductSchema = Joi.object({
  title: Joi.string()
    .required()
    .min(3)
    .error(createError.BadRequest("Incorrect title")),
  description: Joi.string()
    .required()
    .error(createError.BadRequest("Incorrect description")),
  imageLink: Joi.string()
    .required()
    .error(createError.BadRequest("Incorrect imageLink")),
  houseGroup: Joi.string()
    .required()
    .regex(MongoIDPattern)
    .error(createError.BadRequest("Incorrect houseGroup")),
  price: Joi.number()
    .required()
    .error(createError.BadRequest("Incorrect price")),
  discount: Joi.number()
    .allow(0)
    .error(createError.BadRequest("Incorrect discount")),
  offPrice: Joi.number()
    .allow(0)
    .error(createError.BadRequest("Incorrect offPrice")),
  rooms: Joi.number().allow(0).error(createError.BadRequest("Incorrect rooms")),
  parking: Joi.number()
    .allow(0)
    .error(createError.BadRequest("Incorrect parking")),
  warHouse: Joi.number()
    .allow(0)
    .error(createError.BadRequest("Incorrect warHouse")),
  WC: Joi.number().allow(0).error(createError.BadRequest("Incorrect WC")),
  WCType: Joi.string().error(createError.BadRequest("Incorrect WCType")),
  elevator: Joi.number()
    .allow(0)
    .error(createError.BadRequest("Incorrect elevator")),
  floor: Joi.number().allow(0).error(createError.BadRequest("Incorrect floor")),
  collingSystem: Joi.string().error(
    createError.BadRequest("Incorrect collingSystem")
  ),
  heatingSystem: Joi.string().error(
    createError.BadRequest("Incorrect heatingSystem")
  ),
  floorMaterial: Joi.string().error(
    createError.BadRequest("Incorrect heatingSystem")
  ),
  city: Joi.string().error(createError.BadRequest("Incorrect heatingSystem")),
});

const changeCourseDiscountSchema = Joi.object({
  offPrice: Joi.number()
    .required()
    .error(createError.BadRequest("Incorrect offPrice")),
  discount: Joi.number()
    .required()
    .allow(0)
    .error(createError.BadRequest("Incorrect discount")),
});

module.exports = {
  addProductSchema,
  changeCourseDiscountSchema,
};
