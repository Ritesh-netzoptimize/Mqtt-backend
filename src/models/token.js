import mongoose from 'mongoose';
const Schema = mongoose.Schema;

const tokenModel = new Schema({
    refreshToken: { type: String, required: true },
    user: { type: Schema.Types.ObjectId, required: true, ref: 'User' }
})

const Token = mongoose.model('Token', tokenModel);
export default Token;