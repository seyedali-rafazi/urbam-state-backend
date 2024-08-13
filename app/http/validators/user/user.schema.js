const Joi = require("joi");
const createHttpError = require("http-errors");

const getOtpSchema = Joi.object({
  phoneNumber: Joi.string()
    .length(11)
    .pattern(/^09[0-9]{9}$/)
    .error(
      createHttpError.BadRequest("The entered mobile number is not valid")
    ),
});

const checkOtpSchema = Joi.object({
  otp: Joi.string()
    .min(5)
    .max(6)
    .error(createHttpError.BadRequest("The entered code is not valid")),
  phoneNumber: Joi.string()
    .length(11)
    .pattern(/^09[0-9]{9}$/)
    .error(
      createHttpError.BadRequest("The entered mobile number is not valid")
    ),
});

const completeProfileSchema = Joi.object({
  name: Joi.string()
    .min(5)
    .max(100)
    .error(createHttpError.BadRequest("The entered username is not valid")),
  email: Joi.string()
    .email()
    .error(createHttpError.BadRequest("The entered email is not valid")),
  address: Joi.string()
    .min(5)
    .max(100)
    .error(createHttpError.BadRequest("The entered address is not valid")),
});

const updateProfileSchema = Joi.object({
  name: Joi.string()
    .min(5)
    .max(50)
    .error(createHttpError.BadRequest("The entered username is not valid")),
  email: Joi.string()
    .email()
    .error(createHttpError.BadRequest("The entered email is not valid")),
  phoneNumber: Joi.string()
    .length(11)
    .pattern(/^09[0-9]{9}$/)
    .error(
      createHttpError.BadRequest("The entered mobile number is not valid")
    ),
  biography: Joi.string()
    .max(30)
    .allow("")
    .error(createHttpError.BadRequest("The specialty field is not valid.")),
  address: Joi.string()
    .min(5)
    .max(100)
    .error(createHttpError.BadRequest("The entered address is not valid")),
});

module.exports = {
  getOtpSchema,
  completeProfileSchema,
  checkOtpSchema,
  updateProfileSchema,
};
