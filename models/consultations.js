const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const Consultation = sequelize.define('Consultation', {
    id: { 
        type: DataTypes.INTEGER, 
        primaryKey: true, 
        autoIncrement: true 
    },
    user_id: {  // 🔥 Match DB column name
        type: DataTypes.INTEGER, 
        allowNull: false 
    },
    name: { 
        type: DataTypes.STRING(200), 
        allowNull: false 
    },
    email: { 
        type: DataTypes.STRING(255) 
    },
    phone: { 
        type: DataTypes.STRING(20) 
    },
    location: { 
        type: DataTypes.STRING(500), 
        allowNull: false 
    },
    land_size: { 
        type: DataTypes.DECIMAL(10,2) 
    },
    service_type: {  // 🔥 Match DB column name
        type: DataTypes.STRING(100), 
        allowNull: false 
    },
    budget: { 
        type: DataTypes.DECIMAL(15,2) 
    },
    description: { 
        type: DataTypes.TEXT, 
        allowNull: false 
    },
    status: { 
        type: DataTypes.STRING(50), 
        defaultValue: 'pending' 
    },
    created_at: {  // 🔥 Match DB column name
        type: DataTypes.DATE, 
        defaultValue: DataTypes.NOW 
    },
    updated_at: {
        type: DataTypes.DATE
    }
}, {
    tableName: 'consultations',
    timestamps: false,  // We're using created_at/updated_at manually
    underscored: true   // 🔥 This tells Sequelize to use snake_case
});

module.exports = Consultation;