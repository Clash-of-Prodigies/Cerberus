import React from 'react';
import { Routes, Route, } from 'react-router-dom';
import './App.css';

import Register from './pages/Register';
import Login from './pages/Login';
import Verify from './pages/Verify';
import NotFound from './pages/NotFound';

function App() {
	return (
  <Routes>
    <Route index element={<Login />} />
    <Route path="/register" element={<Register />} />
    <Route path="/login" element={<Login />} />
		<Route path="/verify" element={<Verify />} />
    <Route path="*" element={<NotFound />} />
	</Routes>
	);
}

export default App;