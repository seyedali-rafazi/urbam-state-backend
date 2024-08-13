const Controller = require("../../controller");
const { StatusCodes: HttpStatus } = require("http-status-codes");
const createHttpError = require("http-errors");
const {
  addHouseGroupchema,
  updateHouseGroupSchema,
} = require("../../../validators/admin/houseGroup.schema");
const { HousetypesSchemaModel } = require("../../../../models/houseTypes");

class HouseGroupController extends Controller {
  async getListOfHouseGroups(req, res) {
    const query = req.query;
    const houseGroup = await HousetypesSchemaModel.find(query);
    if (!houseGroup)
      throw createHttpError.ServiceUnavailable("No house Group found");

    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        houseGroup,
      },
    });
  }

  async addNewHouseGroup(req, res) {
    const { title, type, englishTitle } =
      await addHouseGroupchema.validateAsync(req.body);
    await this.findHouseGroupWithTitle(englishTitle);
    const houseGroup = await HousetypesSchemaModel.create({
      title,
      englishTitle,
      type,
    });

    if (!houseGroup)
      throw createHttpError.InternalServerError("internal error");
    return res.status(HttpStatus.CREATED).json({
      statusCode: HttpStatus.CREATED,
      data: {
        message: "Nwe houseGroup added",
      },
    });
  }

  async findHouseGroupWithTitle(englishTitle) {
    const houseGroup = await HousetypesSchemaModel.findOne({ englishTitle });
    if (houseGroup) throw createHttpError.BadRequest("houseGroup exist");
  }

  async checkExistHouseGroup(id) {
    const houseGroup = await HousetypesSchemaModel.findById(id);
    if (!houseGroup)
      throw createHttpError.BadRequest("house Group is not exist");
    return houseGroup;
  }

  async updateHouseGroup(req, res) {
    const { id } = req.params;
    const { title, type } = req.body;
    await this.checkExistHouseGroup(id);
    await updateHouseGroupSchema.validateAsync(req.body);
    const updateResult = await HousetypesSchemaModel.updateOne(
      { _id: id },
      {
        $set: { title, type },
      }
    );
    if (updateResult.modifiedCount == 0)
      throw createError.InternalServerError("Update failed");
    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: "Update successful",
      },
    });
  }

  async removeHouseGroup(req, res) {
    const { id } = req.params;
    const houseGroup = await this.checkExist(id);
    const deleteResult = await HousetypesSchemaModel.deleteMany({
      $or: [{ _id: houseGroup._id }, { parentId: houseGroup._id }],
    });
    if (deleteResult.deletedCount == 0)
      throw createError.InternalServerError("Failed to delete");
    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        message: "Deleted successful",
      },
    });
  }

  async getHouseGroupById(req, res) {
    const { id } = req.params;
    const houseGroup = await this.checkExistHouseGroup(id);
    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.OK,
      data: {
        houseGroup,
      },
    });
  }
}

module.exports = {
  HouseGroupController: new HouseGroupController(),
};
