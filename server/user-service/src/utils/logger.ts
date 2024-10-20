//a logger which will print things to console in dev env and send the logs somewhere in prod env

class Logger{
    logger(arg1: any, arg2: any): void;
    logger(arg1: any): void;

    logger(arg1: any, arg2?: any): void{
        if(process.env.NODE_ENV === 'dev'){
            console.log("logger: ");

            if(arg2 === undefined){
                console.log(arg1);
            }else{
                console.log(arg1, arg2);
            }

        }else{
            //do the prod logging here
        }
    }
};

//taken references from prisma class singleton code
//https://www.prisma.io/docs/orm/more/help-and-troubleshooting/help-articles/nextjs-prisma-client-dev-practices
const loggerObject = () => {
    return new Logger().logger;
}

type loggerMethod = ReturnType<typeof loggerObject>

const globalLoggerMethod = globalThis as unknown as {
    logger: loggerMethod | undefined;
};

const logger = globalLoggerMethod.logger ?? loggerObject();

export default logger;

if(process.env.NODE_ENV === 'dev') globalLoggerMethod.logger = logger;






