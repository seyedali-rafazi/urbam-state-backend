const router = require("express").Router();
const expressAsyncHandler = require("express-async-handler");
const {
  HouseGroupController,
} = require("../../http/controllers/admin/houseGroup/houseGroups");

router.post("/add", expressAsyncHandler(HouseGroupController.addNewHouseGroup));
router.patch(
  "/update/:id",
  expressAsyncHandler(HouseGroupController.updateHouseGroup)
);
router.delete(
  "/remove/:id",
  expressAsyncHandler(HouseGroupController.removeHouseGroup)
);

module.exports = {
  houseGroupAdminRoutes: router,
};
