class Helpers {
    constructor() {
        this.generateOTP = this.generateOTP.bind(this);
    }

    getErrorMessage([req, res], error = null) {
        console.log(error, "Error in getErrorMessage");
        // logger.error(error)
        return res.status(422).json({
            "status": "fail",
            "response": error ? error.message : req.t('something_went_wrong')
        });
    }

    getSuccessMessage([req, res], data = null, customObj = null) {
        let response = {
            "status": "success",
            "response": data ? data : req.t('request_process_successfully')
        }
        if (customObj) {
            response = {...response, ...customObj }
        }
        return res.status(200).json(response);
    }

    getValidationErrorMessage([req, res], data = null, customObj = null) {
        console.log(data);
        let response = {
            "status": "fail",
            "response": data ? data : req.t('invalid_parameters')
        }
        if (customObj) {
            response = {...response, ...customObj };
        }
        return res.status(422).json(response);
    }

    generateOTP(min = 100000, max = 900000) {
        return Math.floor(min + Math.random() * max);
        // return Math.floor(Math.random() * (max - min + 1) + min);
    }
}

module.exports = new Helpers();