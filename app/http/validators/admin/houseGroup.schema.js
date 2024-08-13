const Joi = require("joi");
const createHttpError = require("http-errors");

const addHouseGroupchema = Joi.object({
  title: Joi.string()
    .required()
    .min(3)
    .max(100)
    .error(createHttpError.BadRequest("House Group title is not correct")),
  englishTitle: Joi.string()
    .required()
    .min(3)
    .max(100)
    .error(
      createHttpError.BadRequest("House Group englishTitle is not correct")
    ),
  type: Joi.string()
    .required()
    .max(100)
    .valid("housegroups", "post", "comment", "ticket")
    .error(createHttpError.BadRequest("House Group type is not correct")),
});

const updateHouseGroupSchema = Joi.object({
  title: Joi.string()
    .min(3)
    .max(100)
    .error(createHttpError.BadRequest("House Group title is not correct")),
  type: Joi.string()
    .required()
    .min(3)
    .max(100)
    .valid("housegroups", "product", "post", "comment", "ticket")
    .error(createHttpError.BadRequest("House Group type is not correct")),
});

module.exports = {
  addHouseGroupchema,
  updateHouseGroupSchema,
};
