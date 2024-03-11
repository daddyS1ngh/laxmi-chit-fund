exports.resp = (code, object, msg, status = "success") => {
    return {
        code: code,
        data: object,
        message: msg,
        status: status,
    };
}

exports.sum = (a, b) => {
    return a + b;
}