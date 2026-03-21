const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const Consultation = sequelize.define('Consultation', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING(100), allowNull: false },
    phone: { type: DataTypes.STRING(20), allowNull: false },
    email: { type: DataTypes.STRING(100) },
    service: { type: DataTypes.STRING(50), allowNull: false },
    details: { type: DataTypes.TEXT },
    status: { type: DataTypes.ENUM('pending','contacted','in-progress','completed','cancelled'), defaultValue: 'pending' },
    created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, {
    tableName: 'consultations',
    timestamps: false
});

module.exports = Consultation;