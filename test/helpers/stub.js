// Helper class for simple stubbing - No need to use all of sinon for such simple operations
class Stub {
	constructor() {
		this.calledWith = undefined;
		this.callCount = 0;
		this.returns = undefined;
	}
	stub() {
		return (...args) => {
			this.calledWith = args;
			this.calledWithExactly = (...exactArgs) => {
				for(let i=0;i<exactArgs.length;i++) {
					if (i>=this.calledWith.length||exactArgs[i] !== this.calledWith[i]) {
						return false;
					}
				}
				return true;
			};
			this.callCount++;
			return this.returns;
		};
	}
	return(arg) {
		this.returns = arg;
	}
}

export { Stub };