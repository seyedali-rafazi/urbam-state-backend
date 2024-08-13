const expressAsyncHandler = require("express-async-handler");
const {
  HouseGroupController,
} = require("../http/controllers/admin/houseGroup/houseGroups");

const router = require("express").Router();

router.get(
  "/list",
  expressAsyncHandler(HouseGroupController.getListOfHouseGroups)
);

router.get("/:id", expressAsyncHandler(HouseGroupController.getHouseGroupById));
module.exports = {
  houseGroupRoutes: router,
};
