// This is only to be used by bundler, to generate commonjs code
// Normally you want to use main.js

import { ToolBoxRegistration } from "./toolbox.js";
ToolBoxRegistration.registerAsGlobal();

import { Fido2Lib } from "../common/main.js";
export default Fido2Lib;