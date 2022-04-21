import { ToolBoxRegistration } from "./toolbox.js";
ToolBoxRegistration.registerAsGlobal();

import { Fido2Lib } from "../common/main.js";

Fido2Lib.Fido2Lib = Fido2Lib;
export default Fido2Lib;
export { Fido2Lib }; 