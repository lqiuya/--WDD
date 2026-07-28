export namespace main {
	
	export class SecurityCheck {
	    passed: boolean;
	    detail: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new SecurityCheck(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.passed = source["passed"];
	        this.detail = source["detail"];
	        this.value = source["value"];
	    }
	}
	export class ContainerPermission {
	    name: string;
	    has: boolean;
	    dangerous: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ContainerPermission(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.has = source["has"];
	        this.dangerous = source["dangerous"];
	    }
	}
	export class ContainerDetailResult {
	    id: string;
	    name: string;
	    image: string;
	    status: string;
	    securityScore: number;
	    riskLevel: string;
	    user: string;
	    privileged: boolean;
	    readonlyRootfs: boolean;
	    noNewPrivileges: boolean;
	    seccomp: boolean;
	    apparmor: boolean;
	    capAdd: string[];
	    capDrop: string[];
	    permissions: ContainerPermission[];
	    ports: string[];
	    mounts: string[];
	    env: string[];
	    flags: string[];
	    networkMode: string;
	    pidMode: string;
	    ipcMode: string;
	    securityChecks: Record<string, SecurityCheck>;
	
	    static createFrom(source: any = {}) {
	        return new ContainerDetailResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.image = source["image"];
	        this.status = source["status"];
	        this.securityScore = source["securityScore"];
	        this.riskLevel = source["riskLevel"];
	        this.user = source["user"];
	        this.privileged = source["privileged"];
	        this.readonlyRootfs = source["readonlyRootfs"];
	        this.noNewPrivileges = source["noNewPrivileges"];
	        this.seccomp = source["seccomp"];
	        this.apparmor = source["apparmor"];
	        this.capAdd = source["capAdd"];
	        this.capDrop = source["capDrop"];
	        this.permissions = this.convertValues(source["permissions"], ContainerPermission);
	        this.ports = source["ports"];
	        this.mounts = source["mounts"];
	        this.env = source["env"];
	        this.flags = source["flags"];
	        this.networkMode = source["networkMode"];
	        this.pidMode = source["pidMode"];
	        this.ipcMode = source["ipcMode"];
	        this.securityChecks = this.convertValues(source["securityChecks"], SecurityCheck, true);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class ContainerProcess {
	    name: string;
	    pid: number;
	    user: string;
	    status: string;
	    riskLevel: string;
	    riskScore: number;
	    securityScore: number;
	    riskFlags: string[];
	    containerType: string;
	    innerInfo: string;
	    id: string;
	
	    static createFrom(source: any = {}) {
	        return new ContainerProcess(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.pid = source["pid"];
	        this.user = source["user"];
	        this.status = source["status"];
	        this.riskLevel = source["riskLevel"];
	        this.riskScore = source["riskScore"];
	        this.securityScore = source["securityScore"];
	        this.riskFlags = source["riskFlags"];
	        this.containerType = source["containerType"];
	        this.innerInfo = source["innerInfo"];
	        this.id = source["id"];
	    }
	}
	export class ContainerScanResult {
	    success: boolean;
	    totalProcs: number;
	    riskStats: Record<string, number>;
	    processes: ContainerProcess[];
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new ContainerScanResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.totalProcs = source["totalProcs"];
	        this.riskStats = source["riskStats"];
	        this.processes = this.convertValues(source["processes"], ContainerProcess);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ExecuteResult {
	    success: boolean;
	    function: string;
	    output: string;
	    error: string;
	    timestamp: string;
	    needRoot: boolean;
	    rootMsg: string;
	
	    static createFrom(source: any = {}) {
	        return new ExecuteResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.function = source["function"];
	        this.output = source["output"];
	        this.error = source["error"];
	        this.timestamp = source["timestamp"];
	        this.needRoot = source["needRoot"];
	        this.rootMsg = source["rootMsg"];
	    }
	}
	export class FunctionItem {
	    code: string;
	    name: string;
	    number: number;
	    category: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new FunctionItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.name = source["name"];
	        this.number = source["number"];
	        this.category = source["category"];
	        this.description = source["description"];
	    }
	}
	export class HardenContainer {
	    id: string;
	    name: string;
	    image: string;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new HardenContainer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.image = source["image"];
	        this.status = source["status"];
	    }
	}
	export class HardenTask {
	    container_id: string;
	    container_name: string;
	    options: string[];
	
	    static createFrom(source: any = {}) {
	        return new HardenTask(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.container_id = source["container_id"];
	        this.container_name = source["container_name"];
	        this.options = source["options"];
	    }
	}
	export class HardenRequest {
	    tasks: HardenTask[];
	
	    static createFrom(source: any = {}) {
	        return new HardenRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tasks = this.convertValues(source["tasks"], HardenTask);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class HardenResult {
	    success: boolean;
	    container_id: string;
	    container_name: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new HardenResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.container_id = source["container_id"];
	        this.container_name = source["container_name"];
	        this.message = source["message"];
	    }
	}
	export class HardenResponse {
	    results: HardenResult[];
	
	    static createFrom(source: any = {}) {
	        return new HardenResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.results = this.convertValues(source["results"], HardenResult);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class InputType {
	    type: string;
	    category: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new InputType(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.category = source["category"];
	        this.description = source["description"];
	    }
	}
	
	export class ToolStatus {
	    name: string;
	    description: string;
	    installed: boolean;
	    version: string;
	    installCmd: string;
	
	    static createFrom(source: any = {}) {
	        return new ToolStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.installed = source["installed"];
	        this.version = source["version"];
	        this.installCmd = source["installCmd"];
	    }
	}

}

